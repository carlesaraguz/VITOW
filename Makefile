
OBJDIR := obj
ROBJS  := $(addprefix $(OBJDIR)/,vitow_rx.o radiotap.o)
TOBJS  := $(addprefix $(OBJDIR)/,vitow_tx.o)

CFLAGS  = -I../openfec_v1.4.2/src/lib_common -Wall
LDFLAGS = -lopenfec -lm -lpcap -lpthread

all: vitow_rx vitow_tx

$(OBJDIR)/%.o : %.c
	@echo -n -e '---------: COMPILING $< -> $@ : '
	@gcc -c $< -o $@ $(CFLAGS) && echo 'done.'

vitow_tx: $(TOBJS) | $(OBJDIR)
	@echo -n -e '---------: LINKING $< -> $@ : '
	@gcc $(TOBJS) -o $@ $(LDFLAGS) && echo 'done.'

vitow_rx: $(ROBJS) | $(OBJDIR)
	@echo -n -e '---------: LINKING $< -> $@ : '
	@gcc $(ROBJS) -o $@ $(LDFLAGS) && echo 'done.'

$(ROBJS): | $(OBJDIR)

$(TOBJS): | $(OBJDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

clean:
	@echo -n '---------: REMOVING binaries... ' && rm TX RX -f && echo 'done.'
	@echo -n '---------: REMOVING objects... ' && rm $(OBJDIR) -r -f && echo 'done.'
