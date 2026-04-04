.PHONY: all clean

CC = cc
CFLAGS += -O2 -std=c89
CFLAGS += -Wall -Wextra -pedantic
CFLAGS += -I. -Ifunction

FCFILES = $(wildcard function/*/*.c)

NAME = tp
ifeq ($(OS),Windows_NT)
EXE = $(NAME).exe
else
EXE = $(NAME)
endif

OBJDIR = bin
OBJFDIR = $(OBJDIR)/function

OBJFDIRS = $(addprefix $(OBJFDIR)/,$(notdir $(basename $(FCFILES))))

OBJS += $(OBJDIR)/test.o
OBJS += $(patsubst %.c,$(OBJDIR)/%.o,$(FCFILES))

ifeq ($(CC),clang)
CFLAGS += -Wno-newline-eof
endif

all: $(EXE)

clean:
ifneq ($(wildcard $(OBJDIR)/.*),)
	rm -fr $(EXE) $(OBJDIR)
else
	@echo "Already cleaned"
endif

$(EXE): $(OBJS)
	$(CC) -o $@ $^

$(OBJS): | $(OBJDIR) $(OBJFDIRS)

$(OBJDIR):
	mkdir $(OBJDIR)
$(OBJFDIRS):
	mkdir -p $(OBJFDIRS)

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJFDIR)/%/%.o: function/%/%.c
	$(CC) $(CFLAGS) -c -o $@ $<