.PHONY: all clean

SOURCES := $(wildcard *.c)
BASENAMES := $(basename $(SOURCES))
OBJECTS := $(addprefix ../compiled/, $(addsuffix .o, $(BASENAMES)))
EXECUTABLES := $(addprefix ../compiled/, $(BASENAMES))

# Use LLVM_DIR if specified, otherwise use clang from PATH
ifdef LLVM_DIR
CLANG := $(LLVM_DIR)/clang
else
CLANG := clang
endif

all: $(EXECUTABLES)

../compiled/%: %.c | ../compiled
	$(CLANG) -O2 -target parasol -o $@ $<

../compiled:
	mkdir -p $@

clean:
	$(RM) $(EXECUTABLES) $(OBJECTS)
	$(RM) -r ../compiled
