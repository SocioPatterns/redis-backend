Redis Backend for SocioPatterns
===============================

Requirements
------------

1. Install SocioPatterns Python analysis framework (pysopa)

    ```
    git clone https://github.com/SocioPatterns/pysopa.git
    cd pysopa
    python setup.py install
    ```

2. Install Redis (http://redis.io/)

    ```
    wget http://download.redis.io/redis-stable.tar.gz
    tar xvzf redis-stable.tar.gz
    cd redis-stable
    make
    ```

3. Install webdis

    ```
    git clone git://github.com/nicolasff/webdis.git 
    cd webdis
    make
    ```

4. Find out (if necessary) the xxtea cryptographic key (`TEA_CRYPTO_KEY`)

5. Configure `UDP_IP`, `UDP_PORT` and `TEA_CRYPTO_KEY` in ContactReceiver.py.
    If `TEA_CRYPTO_KEY` is not used, set it to `''`.
    `UDP_IP` is the address of the computer that is receiving packets (where ContactReceiver.py is executed).
    `UDP_PORT` is the port to which the UDP packets are sent (default 2342).

6. Run `"export PYTHONPATH={PATH} && python ContactReceiver.py {RUN_NAME}"`,
    where `PATH` is the directory where the script rediscontactadder.py can be found,
    and `RUN_NAME` is the name of the run to be used in the database.
    `RUN_NAME` is the same used afterwards in the popup of the spbrowser page.

7. Start redis from the redis folder (redis-stable/src):

    ```
    ./redis-server
    ```

8. Start webdis from the webdis folder:

    ```
    ./webdis &
    ```

9. Start the SocioPatterns experiment (start the readers and the tags).

10. Download the SocioPatterns Data Browser (spbrowser):

    ```
    git clone https://github.com/SocioPatterns/spbrowser.git
    ```

11. Open with Google Chrome the index.html from spbrowser

12. Insert in the popup the `RUN_NAME` defined in step 6.


Notes
-----
    
- Data is uploaded to the database in `frames`. If you want to upload each event separately, change the code as follows:
    - comment line 65 (`self.pipe = self.rdb.pipeline()`)
    - move line 128 to 125 (`self.pipe = self.rdb.pipeline()`)
    - move line 127 to 143 (`self.pipe.execute()`)

- The SocioPatterns Data Browser (spbrowser) was tested only in Google Chrome.
