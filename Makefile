DEBUG := 0

CFLAGS := -Wall -Wextra -Wpedantic -std=c++20 -Wno-attributes

debug: CFLAGS += -Og -g3 -DWASM_DEBUG -fsanitize=address,undefined
release: CFLAGS += -O2

debug: executable tests

instance.o: instance.cpp instance.hpp
	clang++ instance.cpp -c $(CFLAGS)

module.o: module.cpp module.hpp
	clang++ module.cpp -c $(CFLAGS)

main.o: main.cpp
	clang++ main.cpp -c $(CFLAGS)

tests: instance.o module.o ./test/executor.cpp
	clang++ test/executor.cpp instance.o module.o -o test/executor $(CFLAGS) -lc++

executable: instance.o module.o main.o
	clang++ instance.o module.o main.o -o main $(CFLAGS) -lc++

clean:
	rm -f *.o
	rm -f main
	rm -f test/executor
