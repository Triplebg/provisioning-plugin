/********* marvell-provisioning.m Cordova Plugin Implementation *******/

#import <Cordova/CDV.h>
#import "zlib.h"

#import "arpa/inet.h"
#import "CommonCrypto/CommonCryptor.h"
#import "CommonCrypto/CommonKeyDerivation.h"

/*
#import "Reachability.h"
#import "Constant.h"
#import "ServerRequestDelegate.h"
#import "AppDelegate.h"
#import "MessageList.h"
#import "errno.h"*/

@interface marvell_provisioning : CDVPlugin 
{
  // Member variables go here.	
    // BOOL isChecked;   
    // UIAlertView *alertVw;
    // unsigned char bssid[6];
    // int Mode;
    // int invalidKey;
    // int invalidPassphrase;
    // int invalidCustomData;

	
	//for sure needed
	char passphrase[64];
    char ssid[33];
	int passLen;
	int passLength;
	int customDataLen;
	int encryptedCustomDataLen;
	int TimerCount;
	int timerCount;
	unsigned int ssidLength;
	unsigned long passCRC;
    unsigned long ssidCRC;
    unsigned long customDataCRC;
    unsigned char preamble[6];	
	Byte customData[32];	
	Byte encryptedCustomData[32];
//	NSInteger state;
//	NSInteger substate;
	NSTimer *timer;
    NSTimer *timerMdns;
	
	//Custom Added
	BOOL inProgress;
	NSString* key_;
	NSString* data_;
	NSString* ssid_;
}   NSString* pss_;

@property (strong,atomic) NSMutableArray *services;
@property (assign, nonatomic) NSInteger state;
@property (assign, nonatomic) NSInteger substate;

- (void)SendProvisionData:(CDVInvokedUrlCommand*)command;
@end




@implementation marvell_provisioning

- (void)SendProvisionData:(CDVInvokedUrlCommand*)command
{
    CDVPluginResult* pluginResult = nil;
    NSString* echo = [command.arguments objectAtIndex:0];
	
	ssid_ = [command.arguments objectAtIndex:0];  //txtNetworkName;
	pss_ = [command.arguments objectAtIndex:1];   //txtPassword;
	key_ = [command.arguments objectAtIndex:2];   //txtDeviceKey.text;
	data_ = [command.arguments objectAtIndex:3];  //txtCustomData.text 
	
	preamble[0] = 0x45;
    preamble[1] = 0x5a;
    preamble[2] = 0x50;
    preamble[3] = 0x52;
    preamble[4] = 0x32;
    preamble[5] = 0x32;
	ssidLength = [ssid_ length];
			  
	//strcpy(ssid, [ssid_ UTF8String]);		  
	//strcpy(passphrase, [pss_ UTF8String]);	
	//passLength = [pss_ length];	
	//ssidLength = [ssid_ length];	
	


    if (echo != nil && [echo length] > 0) {
		[self xmitterTask];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:echo];
    } else {
		//[self xmitterTask];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
    }

    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}
/*
-(IBAction)OnProvisionClick:(id)sender
{
    [self.view endEditing:YES];
    if (!invalidKey && !invalidPassphrase && !invalidCustomData) {
        status.text = @"";
        self.btnProvision.enabled = YES;
    } else if (invalidKey) {
        status.text = INVALID_KEY_LENGTH;
        return;
    } else if ([txtCustomData.text length] % 2 || invalidCustomData) {
        status.text = INVALID_CUSTOM_DATA;
        return;
    } else {
        status.text = INVALID_PASSPHRASE_LENGTH;
        return;
    }

    if ([AppDelegate isWiFiReachable]) {
        [self xmitterTask];
    } else {
        [self showMessage:MARVELL_NO_NETWORK withTitle:@""];
        return;
    }
}*/

-(void)xmitterTask
{
    strcpy(ssid, [ssid_ UTF8String]);
    strcpy(passphrase, [pss_ UTF8String]);
    passLength = (int)pss_.length;
    passLen = passLength;
    unsigned char *str_passphrase = (unsigned char *)passphrase;
    unsigned char *str_ssid = (unsigned char *)ssid;
    
    passCRC = crc32(0, str_passphrase, passLen);
    ssidCRC = crc32(0, str_ssid, ssidLength);
    
    passCRC = passCRC & 0xffffffff;
    ssidCRC = ssidCRC & 0xffffffff;
    
    NSString *customDataString = data_;
    for (int i = 0; i < sizeof(customData); i++)
        customData[i] = 0x00;
    if ([customDataString length] % 2) {
        customDataLen = 0;
        customDataCRC = 0;
    } else {
        customDataLen = (int)[customDataString length] / 2;
        for (int i = 0; i < [customDataString length]; i += 2) {
            NSString *word = [customDataString substringWithRange:NSMakeRange(i, 2)];
            unsigned int c;
            [[NSScanner scannerWithString:word] scanHexInt:&c];
            customData[i/2] = c;
        }
        if (customDataLen % 16 == 0) {
            encryptedCustomDataLen = customDataLen;
        } else {
            encryptedCustomDataLen = ((customDataLen / 16) + 1) * 16;
        }
        
        customDataCRC = crc32(0, customData, encryptedCustomDataLen);
        customDataCRC = customDataCRC & 0xffffffff;
    }
    
    if ([key_ length] != 0) {
        char plainpass[100];
        bzero(plainpass, 100);
        char key[100];
        bzero(key, 100);
        int i;
        if (passLen % 16 != 0) {
            passLen = (16 - passLen%16) + passLen;
            for (i = 0; i < passLength; i++)
                plainpass[i] = passphrase[i];
            for (; i < passLen; i++)
                plainpass[i] = 0x00;
        }
        strcpy(key,[key_ UTF8String]);
        for (i = (int)strlen(key); i < 100; i++)
            key[i] = 0x00;
        
        [self myEncryptPassphrase: key passPhrase: plainpass];
        [self myEncryptCustomData: key customData: customData];
    }
    
    inProgress = YES;
    while (inProgress) {
        [self statemachine];
    }
    
    /*
    if (!inProgress) {
        inProgress = YES;
        timer=  [NSTimer scheduledTimerWithTimeInterval:0.001 target:self selector:
                 @selector(statemachine) userInfo:nil repeats:YES];
    } else {
        if ([timer isValid] && [timer isKindOfClass:[NSTimer class]]) {
            [timer invalidate];
            timer = nil;
        }
        _state = 0;
        _substate = 0;
        inProgress = NO;
        //flag = 1;
    }*/
}


-(void) xmitRaw:(int) u data:(int) m substate:(int) l
{
    int sock;
    struct sockaddr_in addr;
    char buf = 'a';
    
    NSMutableString* getnamebyaddr = [NSMutableString stringWithFormat:@"239.%d.%d.%d", u, m, l];
    const char * d_addr = [getnamebyaddr UTF8String];
    //NSLog(@"Sending to: %s",[getnamebyaddr UTF8String]);
    
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        //NSLog(@"ERROR: broadcastMessage - socket() failed");
        return;
    }
    
    bzero((char *)&addr, sizeof(struct sockaddr_in));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(d_addr);
    addr.sin_port        = htons(10000);
    
    if ((sendto(sock, &buf, sizeof(buf), 0, (struct sockaddr *) &addr, sizeof(addr))) != 1) {
        //NSLog(@"Errno %d", errno);
        //NSLog(@"ERROR: broadcastMessage - sendto() sent incorrect number of bytes");
        close(sock);
        return;
    }
    
    close(sock);
}

-(void) myEncryptPassphrase : (char [])key passPhrase:(char [])secret
{
    char dataOut[80];// set it acc ur data
    unsigned char derivedSecret[32];
    bzero(dataOut, sizeof(dataOut));
    bzero(derivedSecret, sizeof(derivedSecret));
    size_t numBytesEncrypted = 0;
    
    int result = CCKeyDerivationPBKDF(kCCPBKDF2, key, strlen(key), (uint8_t *)ssid, ssidLength,
                                      kCCPRFHmacAlgSHA1, 4096, derivedSecret, sizeof(derivedSecret));
    result = (int) CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, derivedSecret, kCCKeySizeAES256, nil, secret, passLen, dataOut, sizeof(dataOut), &numBytesEncrypted);
    
    memcpy(passphrase, dataOut, passLen);
}

-(void) myEncryptCustomData : (char [])key customData:(char [])secret
{
    char dataOut[40];// set it acc ur data
    unsigned char derivedSecret[32];
    bzero(dataOut, sizeof(dataOut));
    bzero(derivedSecret, sizeof(derivedSecret));
    size_t numBytesEncrypted = 0;
    
    int result = CCKeyDerivationPBKDF(kCCPBKDF2, key, strlen(key), (uint8_t *)ssid, ssidLength,
                                      kCCPRFHmacAlgSHA1, 4096, derivedSecret, sizeof(derivedSecret));
    
    result = (int) CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, derivedSecret, kCCKeySizeAES256, nil, secret, encryptedCustomDataLen, dataOut, sizeof(dataOut), &numBytesEncrypted);
    
    memcpy(encryptedCustomData, dataOut, encryptedCustomDataLen);
}

-(void)xmitState0:(int)substate
{
    int i, j, k;
    
    k = preamble[2  * substate];
    j = preamble[2 * substate + 1];
    i = substate | 0x78;
    [self xmitRaw:i data: j substate: k];
}

-(void)xmitState1:(int)substate LengthSSID:(int)len
{
    if (substate == 0) {
        int u = 0x40;
        [self xmitRaw:u data:ssidLength substate: ssidLength];
    } else if (substate == 1 || substate == 2) {
        int k = (int) (ssidCRC >> ((2 * (substate - 1) + 0) * 8)) & 0xff;
        int j = (int) (ssidCRC >> ((2 * (substate - 1) + 1) * 8)) & 0xff;
        int i = substate | 0x40;
        [self xmitRaw:i data: j substate: k];
    } else {
        int u = 0x40 | substate;
        int l = (0xff & ssid[(2 * (substate - 3))]);
        int m;
        if (len == 2)
            m = (0xff & ssid[(2 * (substate - 3) + 1)]);
        else
            m = 0;
        [self xmitRaw:u data:m substate:l];
    }
}

-(void)xmitState2: (int)substate LengthPassphrase:(int)len
{
    if (substate == 0) {
        int u = 0x00;
        [self xmitRaw:u data:passLen substate: passLen];
    } else if (substate == 1 || substate == 2) {
        int k = (int) (passCRC >> ((2 * (substate - 1) + 0) * 8)) & 0xff;
        int j = (int) (passCRC >> ((2 * (substate - 1) + 1) * 8)) & 0xff;
        int i = substate;
        [self xmitRaw:i data: j substate: k];
    } else {
        int u = substate;
        int l = (0xff & passphrase[(2 * (substate - 3))]);
        int m;
        if (len == 2)
            m = (0xff & passphrase[(2 * (substate - 3)) + 1]);
        else
            m = 0;
        [self xmitRaw:u data:m substate:l];
    }
}


-(void)xmitState3:(int)substate LengthCustomData: (int)len
{
    if (substate == 0) {
        int i = 0x60;
        [self xmitRaw:i data:customDataLen substate: customDataLen];
    } else if (substate == 1 || substate == 2) {
        int k = (int) (customDataCRC >> ((2 * (substate - 1) + 0) * 8)) & 0xff;
        int j = (int) (customDataCRC >> ((2 * (substate - 1) + 1) * 8)) & 0xff;
        int i = substate | 0x60;
        [self xmitRaw:i data: j substate: k];
    } else {
        int u = substate | 0x60;
        int l = (0xff & encryptedCustomData[(2 * (substate - 3))]);
        int m;
        if (len == 2)
            m = (0xff & encryptedCustomData[(2 * (substate - 3)) + 1]);
        else
            m = 0;
        [self xmitRaw:u data:m substate:l];
    }
}

-(void)statemachine
{
    NSString *temp;
    if (_state == 0 && _substate == 0) {
        TimerCount++;
        // if (TimerCount % 10 == 0) {
            // temp = [NSString stringWithFormat:@"Information sent %d times.", TimerCount];
            // //status.text = temp;
        // }
    }
    if (TimerCount >= 300) {
        //[self queryMdnsService];
        //NSLog(@"Browsing services");
        
        //status.text = MARVELL_INFO_SENT;
        //timerCount = 15;
        //timerMdns =  [NSTimer scheduledTimerWithTimeInterval:1 target:self selector: @selector(mdnsFound) userInfo:nil repeats:YES];
        
        if ([timer isValid] && [timer isKindOfClass:[NSTimer class]]) {
            [timer invalidate];
            timer = nil;
        }
        _state = 0;
        _substate = 0;
        TimerCount = 0;
        inProgress = NO;
        //flag = 1;
    }
    
    switch(_state) {
        case 0:
            if (_substate == 3) {
                _state = 1;
                _substate = 0;
            } else {
                [self xmitState0:_substate];
                _substate++;
            }
            break;
        case 1:
            
            [self xmitState1:_substate LengthSSID:2];
            _substate++;
            if (ssidLength % 2 == 1) {
                if (_substate * 2 == ssidLength + 5) {
                    [self xmitState1:_substate LengthSSID: 1];
                    _state = 2;
                    _substate = 0;
                }
            } else {
                if ((_substate - 1) * 2 == (ssidLength + 4)) {
                    _state = 2;
                    _substate = 0;
                }
            }
            break;
        case 2:
            [self xmitState2:_substate LengthPassphrase:2];
            
            _substate++;
            if (passLen % 2 == 1) {
                if (_substate * 2 == passLen + 5) {
                    [self xmitState2:_substate LengthPassphrase: 1];
                    _state = 3;
                    _substate = 0;
                }
            } else {
                if ((_substate - 1) * 2 == (passLen + 4)) {
                    _state = 3;
                    _substate = 0;
                }
            }
            break;
        case 3:
            [self xmitState3:_substate LengthCustomData:2];
            
            _substate++;
            if (encryptedCustomDataLen % 2 == 1) {
                if (_substate * 2 == encryptedCustomDataLen + 5) {
                    [self xmitState3:_substate LengthCustomData: 1];
                    _state = 0;
                    _substate = 0;
                }
            } else {
                if ((_substate - 1) * 2 == (encryptedCustomDataLen + 4)) {
                    _state = 0;
                    _substate = 0;
                }
            }
            break;
            
        default:
            //NSLog(@"MRVL: I should not be here!");
    }
}

/*
-(void)xmitterTask
{
    //strcpy(passphrase, [txtPassword.text UTF8String]);
	//strcpy(customData, [data_ UTF8String]);
	//customData = [data_ UTF8String];
	
	// Getting Byte Array from NSString
	const char *utfString = [data_ UTF8String];
	NSData *myData = [NSData dataWithBytes: utfString length: strlen(utfString)];
	[myData getBytes:customData length:32];
	
    //passLength = (int)passphrase.length;
    passLen = passLength;
    unsigned char *str_passphrase = (unsigned char *)passphrase;
    unsigned char *str_ssid = (unsigned char *)ssid;

    passCRC = crc32(0, str_passphrase, passLen);
    ssidCRC = crc32(0, str_ssid, ssidLength);
	//[self generateCRC32:str_passphrase sizeInBytes:passLen    output:passCRC];
	//[self generateCRC32:str_ssid 	   sizeInBytes:ssidLength output:ssidCRC];

    passCRC = passCRC & 0xffffffff;
    ssidCRC = ssidCRC & 0xffffffff;

    NSString *customDataString = data_;
    for (int i = 0; i < sizeof(customData); i++)
        customData[i] = 0x00;
    if ([customDataString length] % 2) {
        customDataLen = 0;
        customDataCRC = 0;
    } else {
        customDataLen = (int)[customDataString length] / 2;
        for (int i = 0; i < [customDataString length]; i += 2) {
            NSString *word = [customDataString substringWithRange:NSMakeRange(i, 2)];
            unsigned int c;
            [[NSScanner scannerWithString:word] scanHexInt:&c];
            customData[i/2] = c;
        }
        if (customDataLen % 16 == 0) {
            encryptedCustomDataLen = customDataLen;
        } else {
            encryptedCustomDataLen = ((customDataLen / 16) + 1) * 16;
        }
        
        customDataCRC = crc32(0, customData, encryptedCustomDataLen);
		//[self generateCRC32:customData sizeInBytes:encryptedCustomDataLen output:customDataCRC];
        customDataCRC = customDataCRC & 0xffffffff;
    }

    if ([key_ length] != 0) {
        char plainpass[100];
        bzero(plainpass, 100);
        char key[100];
        bzero(key, 100);
        int i;
        if (passLen % 16 != 0) {
            passLen = (16 - passLen%16) + passLen;
            for (i = 0; i < passLength; i++)
                plainpass[i] = passphrase[i];
            for (; i < passLen; i++)
                plainpass[i] = 0x00;
        }
        strcpy(key,[key_ UTF8String]);
        for (i = (int)strlen(key); i < 100; i++)
            key[i] = 0x00;

        [self myEncryptPassphrase: key passPhrase: plainpass];
        [self myEncryptCustomData: key customData: customData];
    }

    if (!inProgress) 
	{
		inProgress = YES;
        //NSLog(@"TEXT is %@", _btnProvision.titleLabel.text);
        timer=  [NSTimer scheduledTimerWithTimeInterval:0.001 target:self selector:
                 @selector(statemachine) userInfo:nil repeats:YES];
		
		while(inProgress)
		{
			[self statemachine];
		}
		
    } else {
        if ([timer isValid] && [timer isKindOfClass:[NSTimer class]]) {
            [timer invalidate];
            timer = nil;
        }
        _state = 0;
        _substate = 0;
        //[_btnProvision setTitle:@"START" forState:UIControlStateNormal];
        //flag = 1;
    }
}

-(void) myEncryptPassphrase : (char [])key passPhrase:(char [])secret
{
    char dataOut[80];// set it acc ur data
    unsigned char derivedSecret[32];
    bzero(dataOut, sizeof(dataOut));
    bzero(derivedSecret, sizeof(derivedSecret));
    size_t numBytesEncrypted = 0;

    int result = CCKeyDerivationPBKDF(kCCPBKDF2, key, strlen(key), (uint8_t *)ssid, ssidLength,
                                      kCCPRFHmacAlgSHA1, 4096, derivedSecret, sizeof(derivedSecret));
    result = (int) CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, derivedSecret, kCCKeySizeAES256, nil, secret, passLen, dataOut, sizeof(dataOut), &numBytesEncrypted);

    memcpy(passphrase, dataOut, passLen);
}

-(void) myEncryptCustomData : (char [])key customData:(char [])secret
{
    char dataOut[40];// set it acc ur data
    unsigned char derivedSecret[32];
    bzero(dataOut, sizeof(dataOut));
    bzero(derivedSecret, sizeof(derivedSecret));
    size_t numBytesEncrypted = 0;

    int result = CCKeyDerivationPBKDF(kCCPBKDF2, key, strlen(key), (uint8_t *)ssid, ssidLength,
                                   kCCPRFHmacAlgSHA1, 4096, derivedSecret, sizeof(derivedSecret));

    result = (int) CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, derivedSecret, kCCKeySizeAES256, nil, secret, encryptedCustomDataLen, dataOut, sizeof(dataOut), &numBytesEncrypted);

    memcpy(encryptedCustomData, dataOut, encryptedCustomDataLen);
}

-(void) xmitRaw:(int) u data:(int) m substate:(int) l
{
    int sock;
    struct sockaddr_in addr;
    char buf = 'a';

    NSMutableString* getnamebyaddr = [NSMutableString stringWithFormat:@"239.%d.%d.%d", u, m, l];
    const char * d_addr = [getnamebyaddr UTF8String];

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    	//NSLog(@"ERROR: broadcastMessage - socket() failed");
    	return;
    }

    bzero((char *)&addr, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(d_addr);
    addr.sin_port        = htons(10000);

    if ((sendto(sock, &buf, sizeof(buf), 0, (struct sockaddr *) &addr, sizeof(addr))) != 1) {
        //NSLog(@"Errno %d", errno);
        //NSLog(@"ERROR: broadcastMessage - sendto() sent incorrect number of bytes");
        close(sock);
        return;
    }

    close(sock);
}

-(void)xmitState0:(int)substate
{
    int i, j, k;

    k = preamble[2  * substate];
    j = preamble[2 * substate + 1];
    i = substate | 0x78;
    [self xmitRaw:i data: j substate: k];
}

-(void)xmitState1:(int)substate LengthSSID:(int)len
{
    if (substate == 0) {
        int u = 0x40;
        [self xmitRaw:u data:ssidLength substate: ssidLength];
    } else if (substate == 1 || substate == 2) {
        int k = (int) (ssidCRC >> ((2 * (substate - 1) + 0) * 8)) & 0xff;
        int j = (int) (ssidCRC >> ((2 * (substate - 1) + 1) * 8)) & 0xff;
        int i = substate | 0x40;
        [self xmitRaw:i data: j substate: k];
    } else {
        int u = 0x40 | substate;
        int l = (0xff & ssid[(2 * (substate - 3))]);
        int m;
        if (len == 2)
            m = (0xff & ssid[(2 * (substate - 3) + 1)]);
        else
            m = 0;
        [self xmitRaw:u data:m substate:l];
    }
}

-(void)xmitState2: (int)substate LengthPassphrase:(int)len
{
    if (substate == 0) {
        int u = 0x00;
        [self xmitRaw:u data:passLen substate: passLen];
    } else if (substate == 1 || substate == 2) {
        int k = (int) (passCRC >> ((2 * (substate - 1) + 0) * 8)) & 0xff;
        int j = (int) (passCRC >> ((2 * (substate - 1) + 1) * 8)) & 0xff;
        int i = substate;
        [self xmitRaw:i data: j substate: k];
    } else {
        int u = substate;
        int l = (0xff & passphrase[(2 * (substate - 3))]);
        int m;
        if (len == 2)
            m = (0xff & passphrase[(2 * (substate - 3)) + 1]);
        else
            m = 0;
        [self xmitRaw:u data:m substate:l];
    }
}

-(void)xmitState3:(int)substate LengthCustomData: (int)len
{
    if (substate == 0) {
        int i = 0x60;
        [self xmitRaw:i data:customDataLen substate: customDataLen];
    } else if (substate == 1 || substate == 2) {
        int k = (int) (customDataCRC >> ((2 * (substate - 1) + 0) * 8)) & 0xff;
        int j = (int) (customDataCRC >> ((2 * (substate - 1) + 1) * 8)) & 0xff;
        int i = substate | 0x60;
        [self xmitRaw:i data: j substate: k];
    } else {
        int u = substate | 0x60;
        int l = (0xff & encryptedCustomData[(2 * (substate - 3))]);
        int m;
        if (len == 2)
            m = (0xff & encryptedCustomData[(2 * (substate - 3)) + 1]);
        else
            m = 0;
        [self xmitRaw:u data:m substate:l];
    }
}

-(void)statemachine
{
    NSString *temp;
    if (_state == 0 && _substate == 0) {
        TimerCount++;
        if (TimerCount % 10 == 0) {
            temp = [NSString stringWithFormat:@"Information sent %d times.", TimerCount];
            //status.text = temp;
        }
    }
    if (TimerCount >= 300) {
        [self queryMdnsService];
        //NSLog(@"Browsing services");

        //status.text = MARVELL_INFO_SENT;
        timerCount = 15;
        timerMdns =  [NSTimer scheduledTimerWithTimeInterval:1 target:self selector: @selector(mdnsFound) userInfo:nil repeats:YES];
        
        if ([timer isValid] && [timer isKindOfClass:[NSTimer class]]) {
            [timer invalidate];
            timer = nil;
        }
        _state = 0;
        _substate = 0;
        TimerCount = 0;
		inProgress = NO;
        //[_btnProvision setTitle:@"START" forState:UIControlStateNormal];
        //flag = 1;
    }

    switch(_state) {
        case 0:
            if (_substate == 3) {
                _state = 1;
                _substate = 0;
            } else {
                [self xmitState0:_substate];
                _substate++;
            }
            break;
        case 1:

            [self xmitState1:_substate LengthSSID:2];
            _substate++;
            if (ssidLength % 2 == 1) {
                if (_substate * 2 == ssidLength + 5) {
                    [self xmitState1:_substate LengthSSID: 1];
                    _state = 2;
                    _substate = 0;
                }
            } else {
                if ((_substate - 1) * 2 == (ssidLength + 4)) {
                    _state = 2;
                    _substate = 0;
                }
            }
            break;
        case 2:
            [self xmitState2:_substate LengthPassphrase:2];

            _substate++;
            if (passLen % 2 == 1) {
                if (_substate * 2 == passLen + 5) {
                    [self xmitState2:_substate LengthPassphrase: 1];
                    _state = 3;
                    _substate = 0;
                }
            } else {
                if ((_substate - 1) * 2 == (passLen + 4)) {
                    _state = 3;
                    _substate = 0;
                }
            }
            break;
        case 3:
            [self xmitState3:_substate LengthCustomData:2];
            
            _substate++;
            if (encryptedCustomDataLen % 2 == 1) {
                if (_substate * 2 == encryptedCustomDataLen + 5) {
                    [self xmitState3:_substate LengthCustomData: 1];
                    _state = 0;
                    _substate = 0;
                }
            } else {
                if ((_substate - 1) * 2 == (encryptedCustomDataLen + 4)) {
                    _state = 0;
                    _substate = 0;
                }
            }
            break;

            default:
            //NSLog(@"MRVL: I should not be here!");
				break;
        }
}

-(void)queryMdnsService
{
    NSNetServiceBrowser *serviceBrowser;

    serviceBrowser = [[NSNetServiceBrowser alloc] init];
    [serviceBrowser setDelegate:self];
    [serviceBrowser searchForServicesOfType:@"_ezconnect-prov._tcp" inDomain:@"local"];
}

-(void) mdnsFound
{
    timerCount--;
    if (!timerCount) {
        //status.text = MARVELL_SWITCH_PROV_MODE;
        [timerMdns invalidate];
        timerMdns = nil;
    }
}
*/
@end
