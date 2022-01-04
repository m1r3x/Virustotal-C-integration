default:
        sudo apt install libcurl4-openssl-dev && gcc project.c -o scan -lcurl -lcrypto
clean:
        rm ./scan
run: 
        ./scan