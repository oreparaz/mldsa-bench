# doc/ — build the LaTeX paper.
#   make            # build PDF (two pdflatex passes for cross-refs)
#   make clean      # remove build intermediates (keep PDF)
#   make distclean  # also remove PDF

TEX     := sb-mldsa44.tex
PDF     := $(TEX:.tex=.pdf)
AUX     := $(TEX:.tex=.aux) $(TEX:.tex=.log) $(TEX:.tex=.out) $(TEX:.tex=.toc)

.PHONY: all clean distclean
all: $(PDF)

$(PDF): $(TEX)
	pdflatex -interaction=nonstopmode -halt-on-error $<
	pdflatex -interaction=nonstopmode -halt-on-error $<

clean:
	rm -f $(AUX)

distclean: clean
	rm -f $(PDF)
