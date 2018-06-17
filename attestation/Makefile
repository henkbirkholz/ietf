XML2RFC=xml2rfc
M_VERSION=00

all:	drafts

bootstrap: 
	sudo pip install xml2rfc
draft-sebrand-remote-attestation-models: draft-sebrand-remote-attestation-models.xml
	$(XML2RFC) $< -o $@-$(M_VERSION).txt
publish: draft-sebrand-remote-attestation-models
	cp draft-sebrand-remote-attestation-models-$(M_VERSION).txt versions/$(M_VERSION)/
	cp draft-sebrand-remote-attestation-models.xml versions/$(M_VERSION)/draft-sebrand-remote-attestation-models-$(M_VERSION).xml

drafts: draft-sebrand-remote-attestation-models

.PHONY: clean draft commit
clean:
	/bin/rm -f *.txt

