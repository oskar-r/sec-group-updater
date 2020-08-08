## sec-group-updater
This is a small utility program updating AWS ingress rules across multiple security groups with your current IP-address.

### Example use
```shell
% sec-group-updater --help
Usage of ./sec-group-updater:
  -delete
        delete ingress rule with description tag before setting new (default true)
  -port int
        port to open (default 22)
  -sec-groups string
        comma separated list of security groups if not set all security groups are scanned for tag
  -tag string
        description tag for ingress rule to be added
```

### Build 
```shell
% go build .
```