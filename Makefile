LAMBDA_BUCKET_NAME=
LAMBDA_KEYPOT_KEY=

.PHONY: build push test zip release

build:
	sudo pip install --upgrade --force-reinstall --target . -r requirements.txt

zip:
	zip -r keypot.zip * -x *.git* *.key *.txt

push:
	aws s3 cp keypot.zip s3://$(LAMBDA_BUCKET_NAME)/$(LAMBDA_KEYPOT_KEY)
	aws lambda update-function-code --function-name keypot --s3-bucket $(LAMBDA_BUCKET_NAME) --s3-key $(LAMBDA_KEYPOT_KEY)
	
test:
	echo 'Not yet implemented'
	
release:
	make build
	make zip
	make push