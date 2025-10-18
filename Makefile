.PHONY: all clean fhe-programs

# Default target
all: fhe-programs

# Build FHE programs
fhe-programs:
	$(MAKE) -C fhe-programs/src all

# Clean all build artifacts
clean:
	$(MAKE) -C fhe-programs/src clean

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build all FHE programs (default)"
	@echo "  fhe-programs - Build FHE programs"
	@echo "  clean        - Clean all build artifacts"
	@echo "  help         - Show this help message"

.PHONY: help
