
all: server client

server: vf.cpp
	g++ -lcrypto -pthread vf.cpp -o vf

client: voter-cli.cpp
	g++ -lcrypto voter-cli.cpp -o voter-cli

clean:
	rm -rf *.o vf voter-cli
