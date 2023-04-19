# export LD_LIBRARY_PATH="${PWD}/libmongoose"
 LIBMONGOOSEDIR = libmongoose
 # Note: builds with address sanitizer by default
 TARGETS += mongoose cryptkvs
 # ======================================================================
 # Compiler and Link

 #export LDFLAGS=-L/opt/homebrew/Cellar/openssl@3/3.0.2/lib
 #export CPPFLAGS=-I/opt/homebrew/opt/openssl@1.1/include
 LDFLAGS=-L/opt/homebrew/Cellar/openssl@3/3.0.2/lib
 LDFLAGS += -L$(LIBMONGOOSEDIR)
 CPPFLAGS=-I/opt/homebrew/Cellar/openssl@3/3.0.2/include

 #-I/usr/local/opt/openssl@3/include -L/usr/local/opt/openssl@3/lib
 # a bit more checks
 #LDFLAGS+= -ljson-c
 CFLAGS += -g
 CFLAGS += -I$(LIBMONGOOSEDIR) -pedantic -Wall
 CFLAGS += -Wextra -Wfloat-equal -Wshadow -Wpointer-arith -Wbad-function-cast -Wwrite-strings \
 -Wconversion -Wunreachable-code -Wcast-qual -W -Wformat=2 -Winit-self -Wuninitialized
 CFLAGS += -Wcast-align
 LDLIBS += -lm -lssl -lcrypto -lcurl -ljson-c -lmongoose
 LDDEPS =
 ## may require: export ASAN_OPTIONS=allocator_may_return_null=1
 #               export ASAN_OPTIONS=verify_asan_link_order=0
 CPPFLAGS += -fsanitize=address
 LDFLAGS  += -fsanitize=address
 LDLIBS   += -fsanitize=address
 # add the debug flag
 CPPFLAGS += -DDEBUG
 .PHONY: all

 all:: $(TARGETS)

 SRCS = cryptkvs.c error.c ckvs_local.c ckvs_utils.c ckvs_crypto.c ckvs_io.c ckvs_client.c ckvs_rpc.c ckvs_httpd.c


 mongoose: $(LIBMONGOOSEDIR)/mongoose.c  $(LIBMONGOOSEDIR)/mongoose.h
	make -C $(LIBMONGOOSEDIR)


 OBJS=$(subst .c,.o,$(SRCS))
cryptkvs: $(OBJS) $(LDDEPS)
	$(LINK.o) -o $@ $(OBJS) $(LDLIBS)
#########################################################################
# DO NOT EDIT BELOW THIS LINE
#
.PHONY: depend clean new static-check check release doc
# automatically generate the dependencies
# including .h dependencies !
depend: .depend
.depend: $(SRCS)
	bash -c "cat $(foreach SRC,$(SRCS),<($(CC) $(CFLAGS) -I$(LIBMONGOOSEDIR) -MM -MT $(SRC:.c=.o) $(SRC))) > ./.depend"
ifneq ($(MAKECMDGOALS),clean)
-include .depend
endif
clean::
	-@/bin/rm -f *.o *~  .depend $(TARGETS)
cleanSmall:
	cp ../provided/small.ckvs ../done/
new: clean all
static-check:
	CCC_CC=$(CC) scan-build -analyze-headers --status-bugs -maxloop 64 make -j1 new
style:
	astyle -n -o -A8 -xt0 *.[ch]
check:
	make -B -C ../tests/end-to-end
	make -B -C ../tests/unit
##	make -B -C ../tests/fuzzing
## --------------------------------------------------
# target to do all checks before releasing a new version by staff
release: new check style static-check clean
## --------------------------------------------------
# target to make documentation
doc: Doxyfile
	doxygen Doxyfile
 ## ======================================================================
 ## Feedback
IMAGE := chappeli/pps22-feedback:week13
  ## Note: vous pouvez changer le tag latest pour week04, ou week05, etc.
 REPO := $(shell git config --get remote.origin.url)
SSH_DIR := $(HOME)/.ssh
.PHONY: feedback feedback-VM-CO clone-ssh clean-fake-ssh
feedback:
	@echo Will use $(REPO) inside container
	@docker pull $(IMAGE)
	@docker run -it --rm -e REPO=$(REPO) -v $(SSH_DIR):/opt/.ssh $(IMAGE)
clone-ssh:
	@-$(eval SSH_DIR := $(HOME)/.$(shell date "+%s;$$"|sha256sum|cut -c-32))
	@cp -r $(HOME)/.ssh/. $(SSH_DIR)
clean-fake-ssh:
	@case $(SSH_DIR) in $(HOME)/\.????????????????????????????????) $(RM) -fr $(SSH_DIR) ;; *) echo "Dare not remove \"$(SSH_DIR)\"" ;; esac
feedback-VM-CO: clone-ssh feedback clean-fake-ssh
## ======================================================================
## Submit
SUBMIT_SCRIPT=../provided/submit.sh
.PHONY: submit1 submit2 submit
submit1: $(SUBMIT_SCRIPT)
	@$(SUBMIT_SCRIPT) 1
submit2: $(SUBMIT_SCRIPT)
	@$(SUBMIT_SCRIPT) 2
submit:
	@printf 'what "make submit"??\nIt'\''s either "make submit1" or "make submit2"...\n''