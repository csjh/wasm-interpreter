DEBUG := 0

CFLAGS := -Wall -Wextra -std=c++20

debug: CFLAGS += -g3 -DWASM_DEBUG -fsanitize=address
release: CFLAGS += -O2

debug: executable tests

interpreter.o: interpreter.cpp interpreter.hpp
	clang++ interpreter.cpp -c $(CFLAGS)

validator.o: validator.cpp validator.hpp
	clang++ validator.cpp -c $(CFLAGS)

main.o: main.cpp
	clang++ main.cpp -c $(CFLAGS)

tests: interpreter.o validator.o ./test/executor.cpp
	clang++ test/executor.cpp interpreter.o validator.o -o test/executor $(CFLAGS)

executable: interpreter.o validator.o main.o
	clang++ interpreter.o validator.o main.o -o main $(CFLAGS)

clean:
	rm -f *.o
	rm main
	rm test/executor
