This repository hosts a module for the ZNC bouncer software available at http://znc.in/

When connected securely (SSL/TLS) to a server with ZNC; this module sends the certificate chain information for the server to the client.

## Usage Instructions

The tlsinfo module sends certificate information on-demand. 

• To view details of the peer certificate and no other certificates:

```
/msg *tlsinfo cert
```

• To view details of the entire certificate chain:

```
/msg *tlsinfo cert details
```

• To view the protocol and cipher suite used for the active connection:

```
/msg *tlsinfo cert cipher
```

• To add the fingerprint of the peer certificate to ZNC's trust store:

```
/msg *tlsinfo cert addtrust
```

• To remove the fingerprint of the peer certificate from ZNC's trust store:

```
/msg *tlsinfo cert removetrust
```


## Raw certificate data

The tlsinfo module is capable of sending certificate data to the connected client in [PEM](https://en.wikipedia.org/wiki/Privacy-enhanced_Electronic_Mail) format so that the client can present the information in a user friendly way such as a dialog.

It is recommended that the connected client requests certificate information when raw numeric 001 (RPL_WELCOME) is received so that the certificate information is available at all times for the end user.

Example of requesting data using ``PRIVMSG`` command syntax:

```
PRIVMSG *tlsinfo :send-data
```

## Enabling access to raw certificate data

The tlsinfo module advertises a custom [IRCv3 capacity (CAP)](http://ircv3.net/specs/core/capability-negotiation-3.2.html) named ``znc.in/tlsinfo``. A client must acknowledge support for this capacity in order to receive data.

Additionally, the tlsinfo module sends data in batches which means the client must also support the [batch](http://ircv3.net/specs/extensions/batch-3.2.html) capacity.

## Recieving raw certificate data

The tlsinfo module sends information in a very specific format:

* Data received from the tlsinfo module is encapsulated in a global ``BATCH`` command with the type: ``znc.in/tlsinfo``
* Each certificate of the certificate chain is within its own nested ``BATCH`` command with the type ``znc.in/tlsinfo``
* Each certificate is sent in [PEM](https://en.wikipedia.org/wiki/Privacy-enhanced_Electronic_Mail) format which is multi-line. Each line is represented by the custom ``tlsinfo`` command. A client can assemble the contents of each nested batch to create a complete certificate. 

The following example is the certificate chain for freenode:

```
<< PRIVMSG *tlsinfo :send

>> :znc.in BATCH +128f2a znc.in/tlsinfo
>> @batch=128f2a :znc.in BATCH +9dc26d znc.in/tlsinfo-certificate
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :-----BEGIN CERTIFICATE-----
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :MIIE5jCCA86gAwIBAgIRAJ70g1ynPi73TW3fbOaE2pUwDQYJKoZIhvcNAQEFBQAw
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :QTELMAkGA1UEBhMCRlIxEjAQBgNVBAoTCUdBTkRJIFNBUzEeMBwGA1UEAxMVR2Fu
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :ZGkgU3RhbmRhcmQgU1NMIENBMB4XDTE1MDEwMzAwMDAwMFoXDTE2MDExNTIzNTk1
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :OVowYjEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMSQwIgYDVQQL
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :ExtHYW5kaSBTdGFuZGFyZCBXaWxkY2FyZCBTU0wxFzAVBgNVBAMUDiouZnJlZW5v
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :ZGUubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7skEb2vyiMg0
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :AepY0fhGs1QcKXqtKNESO1JnqTZN4b7EP/63vKHzJ8/IovUs5XiB2+ILrEPv22q5
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :zNr//3ZgyzbpnNWeZ38mVQaa6yUEIoHR8vTqJljNqi2wIRXnjTMnBIYWjiGFymrI
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :MhjeTpP/zp+h7GFPx7EE9G36yIp5h1d28vWwhGB14aOtiPhvxUzuRSs2jkvEco0A
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :r88Ht3kHtboiFSNUYIVQtF1flbbovc/hxL2xIpSEidwfk1g8eP+g+bMgW2JcwzX2
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :JoH0k4r8N3KdI5oN4t4zXXaKq8GXYBB+CbRnQKIMp/d7fltIjbMr5wbXrNX2l5Vn
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :OoSW9DsfaQIDAQABo4IBtjCCAbIwHwYDVR0jBBgwFoAUtqj/oqgv0KbNS7Fo8+dQ
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :EDGneSEwHQYDVR0OBBYEFEJE/NOiXurJ03ii77Ze+juIGiEwMA4GA1UdDwEB/wQE
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :AwIFoDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :AjBgBgNVHSAEWTBXMEsGCysGAQQBsjEBAgIaMDwwOgYIKwYBBQUHAgEWLmh0dHA6
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :Ly93d3cuZ2FuZGkubmV0L2NvbnRyYWN0cy9mci9zc2wvY3BzL3BkZi8wCAYGZ4EM
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :AQIBMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuZ2FuZGkubmV0L0dhbmRp
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :U3RhbmRhcmRTU0xDQS5jcmwwagYIKwYBBQUHAQEEXjBcMDcGCCsGAQUFBzAChito
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :dHRwOi8vY3J0LmdhbmRpLm5ldC9HYW5kaVN0YW5kYXJkU1NMQ0EuY3J0MCEGCCsG
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :AQUFBzABhhVodHRwOi8vb2NzcC5nYW5kaS5uZXQwJwYDVR0RBCAwHoIOKi5mcmVl
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :bm9kZS5uZXSCDGZyZWVub2RlLm5ldDANBgkqhkiG9w0BAQUFAAOCAQEAmQdK+2u0
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :YiJtu7xKmvTAdIWCbOITm/c8QtukmrMce9HSJdNmRWxpAtr4JdvY7g+hbp/7p335
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :XhVj9Hrbg7wrP+kSL4bmLSicZEHfabHtExSB7NXjzWKIqTxQ6bVrYfnfYz3YbmJ+
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :P1d7d9XCy6bIyLlLz4bnW3Mq1/vgXep/rhaW9nnkts2TQw6WBC8a2ssgrDXEN/K+
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :MrxgzKsTRFal+yTcsJRO5PuQ+W/eWkA+APt15i/d07UZwcVRisPQ4mGtv8ZKS8ft
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :GmhvyTQ2/rstd9P0S2NGq5RiNX3dtxBiiZp7Wn7Xwkfq3vU11BkVDh42Q3sUefYL
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :1K2fg+sOwxqj5g==
>> @batch=9dc26d :znc.in tlsinfo ExampleUser :-----END CERTIFICATE-----
>> @batch=128f2a :znc.in BATCH -9dc26d
>> @batch=128f2a :znc.in BATCH +8b8b0c znc.in/tlsinfo-certificate
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :-----BEGIN CERTIFICATE-----
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :MIIEozCCA4ugAwIBAgIQWrYdrB5NogYUx1U9Pamy3DANBgkqhkiG9w0BAQUFADCB
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :lzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2Ug
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :Q2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExho
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :dHRwOi8vd3d3LnVzZXJ0cnVzdC5jb20xHzAdBgNVBAMTFlVUTi1VU0VSRmlyc3Qt
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :SGFyZHdhcmUwHhcNMDgxMDIzMDAwMDAwWhcNMjAwNTMwMTA0ODM4WjBBMQswCQYD
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :VQQGEwJGUjESMBAGA1UEChMJR0FOREkgU0FTMR4wHAYDVQQDExVHYW5kaSBTdGFu
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :ZGFyZCBTU0wgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2VD2l
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :2w0ieFBqWiOJP5eh1AcaqVgIm6AVwzK2t/HouaVvrTf2bnEbtHUtSF6fxhWqge/l
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :xIiVijpsd8y1zWXkZ+VzyVBSlMEnST6ga0EWQbaUmUGuPsviBkYJ6U2+yUxVqRh+
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :pt9u/UqyzGxO2chQFZOz8unjwmqtOtX7w3lQnyV5KbJHZHwgPuIITZMpFLY0bs9x
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :Rn52EPT9bKoB0sIG3pKDzFiQLpLeHmW3Yy89sutwjEzgvhWd3sFNVvgLxo4HuV3f
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :lfB7QB8aLNecK0t29Fn1Q8EsZhCenmaWYJ0cdBtOGFwIsG5symkaAum7ynjvZi7j
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :Mv1BXJV0gU302v5LAgMBAAGjggE+MIIBOjAfBgNVHSMEGDAWgBShcl8mGyiYQ5Vd
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :BzfVhZadS9LDRTAdBgNVHQ4EFgQUtqj/oqgv0KbNS7Fo8+dQEDGneSEwDgYDVR0P
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :AQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwGAYDVR0gBBEwDzANBgsrBgEE
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :AbIxAQICGjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8vY3JsLnVzZXJ0cnVzdC5j
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :b20vVVROLVVTRVJGaXJzdC1IYXJkd2FyZS5jcmwwdAYIKwYBBQUHAQEEaDBmMD0G
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :CCsGAQUFBzAChjFodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVROQWRkVHJ1c3RT
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :ZXJ2ZXJfQ0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3Qu
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :Y29tMA0GCSqGSIb3DQEBBQUAA4IBAQAZU78DPZvia1r9ukkfT+zhxoI5PNIDBA+r
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :ez6CqYUQH/TeMq9YP/9w8zAdly1MmuLsDD4ULS+YSJ2uFmqsLUKqtWSkcLvrc5R7
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :RkznehR2W0wdhKEgdB8uS1xwiNy99xk97VkN4j8m4pyspDyVHPi+jAOu8OWcTbzH
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :m1gAv6+t+jducW0YNA7B6mr4Dd9pVFYV8iiz/qRj7MUEZGC7/irw9IehsK69quQv
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :4wMLL2ZfhaQye0btJQzn8bfnGf1gul+Hd96YB5bkXupjfajeVdphXDyQg0MEBzzd
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :8/ifBlIK3se2e4/hEfcEejX/arxbx1BJCHBvlEPNnsdw8dvQbdqP
>> @batch=8b8b0c :znc.in tlsinfo ExampleUser :-----END CERTIFICATE-----
>> @batch=128f2a :znc.in BATCH -8b8b0c
>> :znc.in BATCH -128f2a
```

Once data is reassembled, it can then be presented to the end user using a friendly dialog. 

For example:

![Certificate Information Dialog](http://i.imgur.com/kxvehhn.png)
