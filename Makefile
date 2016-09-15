
OBJDIR := obj
ROBJS  := $(addprefix $(OBJDIR)/,RX.o radiotap.o)
TOBJS  := $(addprefix $(OBJDIR)/,TX.o radiotap.o)

CFLAGS  = -I../openfec_v1.4.2/src/lib_common -w
LDFLAGS = -lopenfec -lm -lpcap -lpthread

all: RX TX

$(OBJDIR)/%.o : %.c
	@echo -n -e '---------: COMPILING $< -> $@ : '
	@gcc -c $< -o $@ $(CFLAGS) && echo 'done.'

TX: $(TOBJS) | $(OBJDIR)
	@echo -n -e '---------: LINKING $< -> $@ : '
	@gcc $(TOBJS) -o $@ $(LDFLAGS) && echo 'done.'

RX: $(ROBJS) | $(OBJDIR)
	@echo -n -e '---------: LINKING $< -> $@ : '
	@gcc $(ROBJS) -o $@ $(LDFLAGS) && echo 'done.'

$(ROBJS): | $(OBJDIR)

$(TOBJS): | $(OBJDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

clean:
	@echo -n '---------: REMOVING binaries... ' && rm TX RX -f && echo 'done.'
	@echo -n '---------: REMOVING objects... ' && rm $(OBJDIR) -r -f && echo 'done.'
