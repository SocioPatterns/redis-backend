#!/usr/bin/env python

import redis
import time


class RedisContactAdder:

    def __init__(self, run_name="", start_time='', deltat=20,
                 host='localhost', port=6379, password=None):
        self.RUN = run_name
        self.DELTAT = deltat
        self.START_TIME = start_time if start_time else int(time.time())
        self.host = host
        self.port = port
        self.rdb = redis.StrictRedis(host=host, port=port, password=password)

        self.frame_actors = dict()
        self.frame_interactions = dict()

        self.tline_key = '%s:timeline' % self.RUN
        self.actors_key = '%s:actors' % self.RUN
        self.interactions_key = '%s:interactions' % self.RUN
        self.run_key = '%s:run' % self.RUN

        try:
            self.current_frame, self.last_frametime = self.rdb.zrange(self.tline, -1, -1, withscores=True)[0]
        except:
            self.last_frametime = 0

        self.pipe = self.rdb.pipeline()

        self.pipe.hset(self.run_key, "timeline", self.tline_key)
        self.pipe.hset(self.run_key, "actors", self.actors_key)
        self.pipe.hset(self.run_key, "interactions", self.interactions_key)
        self.pipe.hsetnx(self.run_key, "start_time", self.START_TIME)
        self.pipe.hset(self.run_key, "deltat", self.DELTAT)
        self.pipe.execute()

        lua = """
            local value = redis.call('HSETNX', KEYS[1], 'id', ARGV[1])
            if tonumber(value) > 0
            then
                redis.call('HMSET', KEYS[1], 'timeline', KEYS[1]..':timeline', 'name', 'actor_'..ARGV[1])
                return redis.call('HINCRBY', KEYS[2], 'N_actors', 1)
            end
            return 0
            """

        self.if_new_actor_incr_N = self.rdb.register_script(lua)

        lua = """
            local value = redis.call('HSETNX', KEYS[1], 'actor1', ARGV[1])
            if tonumber(value) > 0
            then
                redis.call('HSET', KEYS[1], 'actor2', ARGV[2])
                redis.call('HSET', KEYS[1], 'timeline', KEYS[1]..':timeline')
                return redis.call('HINCRBY', KEYS[2], 'N_interactions', 1)
            end
            return 0
            """

        self.if_new_interaction_incr_N = self.rdb.register_script(lua)

        self.pipe = self.rdb.pipeline()

    def __timestamp2frame_time(self, timestamp):
        return self.START_TIME + (timestamp - self.START_TIME) // self.DELTAT * self.DELTAT

    def __add_frame(self, frame_time):
        self.pipe.execute()
        self.pipe = self.rdb.pipeline()
        self.last_frametime = frame_time
        self.current_frame_key = '%s:frame:%d' % (self.RUN, frame_time)
        self.pipe.hset(self.current_frame_key, "timestamp", frame_time)
        self.pipe.hset(self.current_frame_key, "timestamp_end", frame_time + self.DELTAT)
        self.pipe.hset(self.current_frame_key, "time", time.ctime(frame_time))
        self.pipe.hset(self.current_frame_key, "length", self.DELTAT)
        self.pipe.hset(self.current_frame_key, "interactions", "%s:interactions" % self.current_frame_key)

        self.pipe.zadd(self.tline_key, frame_time, self.current_frame_key)
        self.pipe.hset(self.run_key, "stop_time", frame_time + self.DELTAT)
        self.pipe.hincrby(self.run_key, "N_frames")

    def __add_interaction(self, actor_id1, actor_id2):
        interaction_key = '%s:interaction:%d-%d' % (self.RUN, actor_id1, actor_id2)
        self.if_new_interaction_incr_N(keys=[interaction_key, str(self.run_key)],
                                       args=[actor_id1, actor_id2], client=self.pipe)
        self.pipe.sadd(self.interactions_key, interaction_key)
        return interaction_key

    def __add_actor(self, actor_id):
        actor_key = '%s:actor:%d' % (self.RUN, actor_id)
        self.if_new_actor_incr_N(keys=[actor_key, str(self.run_key)],
                                 args=[actor_id], client=self.pipe)
        self.pipe.sadd(self.actors_key, actor_key)
        return actor_key

    def __actor_frame(self, actor_key, frame_time):
        self.pipe.zadd('%s:timeline' % actor_key, frame_time, self.current_frame_key)
        self.pipe.sadd('%s:actors' % self.current_frame_key, actor_key)

    def __interaction_frame(self, interaction_key, frame_time):
        self.pipe.zadd('%s:timeline' % interaction_key, frame_time, self.current_frame_key)
        self.pipe.zincrby('%s:interactions' % self.current_frame_key, interaction_key, 1)

    def __actor_interaction(self, actor_key, interaction_key):
        self.pipe.sadd('%s:interactions' % actor_key, interaction_key)

    def store_contact(self, contact):
        timestamp = contact.t
        id1 = contact.id
        for id2 in contact.seen_id:
            self.add_single_contact(timestamp, id1, id2)

    def add_single_contact(self, timestamp, actor_id1, actor_id2):
        actor_id1, actor_id2 = sorted([actor_id1, actor_id2])
        frame_time = self.__timestamp2frame_time(timestamp)

        if frame_time > self.last_frametime:
            self.pipe.execute()
            self.pipe = self.rdb.pipeline()
            self.__add_frame(frame_time)

        actor1_key = self.__add_actor(actor_id1)
        self.__actor_frame(actor1_key, frame_time)

        actor2_key = self.__add_actor(actor_id2)
        self.__actor_frame(actor2_key, frame_time)

        interaction_key = self.__add_interaction(actor_id1, actor_id2)
        self.__actor_interaction(actor1_key, interaction_key)
        self.__actor_interaction(actor2_key, interaction_key)
        self.__interaction_frame(interaction_key, frame_time)
