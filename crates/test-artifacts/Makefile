all:
	for dir in programs/*/ ; do \
		echo "Building in $${dir}..."; \
		cd $${dir} && cargo monerochan build || { echo "Failed at command: cd $${dir} && cargo monerochan build"; exit 1; }; \
		cd ../..; \
	done

.PHONY: all
