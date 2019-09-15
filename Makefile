.phony: clean all

all:
	cd aggregator && make all
	cd node && make all

clean:
	cd aggregator && make clean
	cd node && make clean

