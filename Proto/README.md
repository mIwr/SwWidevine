#  Proto models

All proto models have proto3 syntax

Protobuf models are visible outside of framework context

## Proto compile

```
protoc --proto_path=. *.proto --swift_opt=Visibility=public --swift_out=../Sources/SwWidevine/Generated/Proto
```
