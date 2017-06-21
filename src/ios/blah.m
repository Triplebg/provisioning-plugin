//
//  StartProvisionViewController.m
//  Marvell
//
//  Copyright (c) 2014 Marvell. All rights reserved.
//

#import "StartProvisionViewController.h"
#import <SystemConfiguration/CaptiveNetwork.h>
#import "Reachability.h"
#import "Constant.h"
#import "ServerRequestDelegate.h"
#import "AppDelegate.h"
#import "MessageList.h"
#import "errno.h"
#import "arpa/inet.h"
#import "zlib.h"
#import "CommonCrypto/CommonCryptor.h"
#import "CommonCrypto/CommonKeyDerivation.h"

@interface StartProvisionViewController ()
{
}

@end

@implementation StartProvisionViewController

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (BOOL)prefersStatusBarHidden
{
    if (IOS_9_0_OR_LATER) {
        return YES;
    }
    return NO;
}

int alertFlag = 0;

/* This function is called when app is loaded on the device */
- (void)viewDidLoad
{
    self.state = 0;
    self.substate = 0;
    Mode = -1;

    if (alertFlag == 0) {
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"EZConnect" message:@"For internal use only. Do not distribute this app.\r\n Copyright (c) 2016 Marvell." delegate:self cancelButtonTitle:@"Ok" otherButtonTitles:nil, nil];
        [alert show];
        [alert release];
        alertFlag = 1;
    }

    [super viewDidLoad];

    txtNetworkName.enabled = NO;
    self.imgViewDDown.layer.cornerRadius = 5.0;
    status.text = MARVELL_APP_STARTED;

    TimerCount = 0;

    // Do any additional setup after loading the view from its nib.
    isChecked = YES;
    [self performSelector:@selector(checkWifiConnection) withObject:nil afterDelay:0.1];
}

-(void)viewWillAppear:(BOOL)animated
{
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(checkWifi)
                                                 name:UIApplicationWillEnterForegroundNotification
                                               object:nil];
    [super viewWillAppear:YES];
}

-(void)viewDidDisappear:(BOOL)animated
{
    [super viewDidDisappear:YES];
    [[NSNotificationCenter defaultCenter] removeObserver:self name:UIApplicationWillEnterForegroundNotification object:nil];
}

/* Action invoked when provision button is clicked */
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
}

/* To mask and unmask the passphrase */
- (IBAction)UnmaskPassword:(id)sender
{
    NSString *tmpString;
    UIButton *btnSender = (UIButton*)sender;
    btnSender.selected = !btnSender.selected;
    if (btnSender.selected) {
        txtPassword.secureTextEntry = NO;
        /* to adjust the cursor position */
        tmpString = txtPassword.text;
        txtPassword.text = @" ";
        txtPassword.text = tmpString;
    } else {
        txtPassword.secureTextEntry = YES;
        /* to adjust the cursor position */
        tmpString = txtPassword.text;
        txtPassword.text = @" ";
        txtPassword.text = tmpString;
    }
}

/* Action invoked on clicking remember passphrase */
- (IBAction)RememberPassword:(id)sender
{
    UIButton *btnSender = (UIButton*)sender;
    btnSender.selected = !btnSender.selected;
    if (btnSender.selected) {
        NSString *keyValue = txtNetworkName.text;
        NSString *valueToSave = txtPassword.text;
        [[NSUserDefaults standardUserDefaults] setObject:valueToSave forKey:keyValue];
    } else {
        NSString *keyValue = txtNetworkName.text;
        NSString *valueToSave = @"NULL";
        [[NSUserDefaults standardUserDefaults] setObject:valueToSave forKey:keyValue];
    }
}

/* Virtual action invoked by program to disable remember passphrase*/
- (IBAction)DisableRememberPassword:(id)sender
{
    UIButton *btnSender = (UIButton*)sender;
    btnSender.selected = NO;
}

- (id)init
{
    NSLog(@"Initializing browser");
    self = [super init];
    if (self) {
        self.services = [NSMutableArray arrayWithCapacity: 0];
    }
    return self;
}

int flag = 1;
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser
           didFindService:(NSNetService *)aNetService
               moreComing:(BOOL)moreComing
{
    [self.services addObject:aNetService];
    const char *serviceType = [[aNetService type] cStringUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"Got service %p with serviceType %s %@ %@\n", aNetService,
          serviceType, [aNetService name], [aNetService type]);
    if (flag && !strncasecmp(serviceType, "_ezconnect-prov._tcp.", sizeof("_ezconnect-prov._tcp."))) {
        NSString *text = [NSString stringWithFormat:@"Device %@ is successfully provisioned to Home Network", [aNetService name]];
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Device Status" message:text delegate:self cancelButtonTitle:@"Ok" otherButtonTitles:@"Cancel", nil];
        [alert show];
        status.text = text;
        if (timerMdns.isValid && [timerMdns isKindOfClass:[NSTimer class]]) {
            [timerMdns invalidate];
            timerMdns = nil;
        }
        flag = 0;
        [text release];
    }

    if(!moreComing)
    {;
        NSLog(@"More coming");
    }
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser
             didNotSearch:(NSDictionary *)errorDict
{
    NSLog(@"Failed searching");
}

-(void)queryMdnsService
{
    NSNetServiceBrowser *serviceBrowser;

    serviceBrowser = [[NSNetServiceBrowser alloc] init];
    [serviceBrowser setDelegate:self];
    [serviceBrowser searchForServicesOfType:@"_ezconnect-prov._tcp" inDomain:@"local"];
}

int timerCount;

-(void) mdnsFound
{
    timerCount--;
    if (!timerCount) {
        status.text = MARVELL_SWITCH_PROV_MODE;
        [timerMdns invalidate];
        timerMdns = nil;
    }
}

#pragma mark - TapGesture Recognizer
-(void) xmitRaw:(int) u data:(int) m substate:(int) l
{
    int sock;
    struct sockaddr_in addr;
    char buf = 'a';

    NSMutableString* getnamebyaddr = [NSMutableString stringWithFormat:@"239.%d.%d.%d", u, m, l];
    const char * d_addr = [getnamebyaddr UTF8String];

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    	NSLog(@"ERROR: broadcastMessage - socket() failed");
    	return;
    }

    bzero((char *)&addr, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(d_addr);
    addr.sin_port        = htons(10000);

    if ((sendto(sock, &buf, sizeof(buf), 0, (struct sockaddr *) &addr, sizeof(addr))) != 1) {
        NSLog(@"Errno %d", errno);
        NSLog(@"ERROR: broadcastMessage - sendto() sent incorrect number of bytes");
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
        if (TimerCount % 10 == 0) {
            temp = [NSString stringWithFormat:@"Information sent %d times.", TimerCount];
            status.text = temp;
        }
    }
    if (TimerCount >= 300) {
        [self queryMdnsService];
        NSLog(@"Browsing services");

        status.text = MARVELL_INFO_SENT;
        timerCount = 15;
        timerMdns =  [NSTimer scheduledTimerWithTimeInterval:1 target:self selector: @selector(mdnsFound) userInfo:nil repeats:YES];
        
        if ([timer isValid] && [timer isKindOfClass:[NSTimer class]]) {
            [timer invalidate];
            timer = nil;
        }
        _state = 0;
        _substate = 0;
        TimerCount = 0;
        [_btnProvision setTitle:@"START" forState:UIControlStateNormal];
        flag = 1;
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
            NSLog(@"MRVL: I should not be here!");
        }
}

-(void)xmitterTask
{
    strcpy(passphrase, [txtPassword.text UTF8String]);
    passLength = (int)txtPassword.text.length;
    passLen = passLength;
    unsigned char *str_passphrase = (unsigned char *)passphrase;
    unsigned char *str_ssid = (unsigned char *)ssid;

    passCRC = crc32(0, str_passphrase, passLen);
    ssidCRC = crc32(0, str_ssid, ssidLength);

    passCRC = passCRC & 0xffffffff;
    ssidCRC = ssidCRC & 0xffffffff;

    NSString *customDataString = txtCustomData.text;
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

    if ([txtDeviceKey.text length] != 0) {
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
        strcpy(key,[txtDeviceKey.text UTF8String]);
        for (i = (int)strlen(key); i < 100; i++)
            key[i] = 0x00;

        [self myEncryptPassphrase: key passPhrase: plainpass];
        [self myEncryptCustomData: key customData: customData];
    }

    if ([[[_btnProvision titleLabel] text] isEqualToString:@"START"]) {
        [_btnProvision setTitle:@"STOP" forState:UIControlStateNormal];
        NSLog(@"TEXT is %@", _btnProvision.titleLabel.text);
        timer=  [NSTimer scheduledTimerWithTimeInterval:0.001 target:self selector:
                 @selector(statemachine) userInfo:nil repeats:YES];
    } else {
        if ([timer isValid] && [timer isKindOfClass:[NSTimer class]]) {
            [timer invalidate];
            timer = nil;
        }
        _state = 0;
        _substate = 0;
        [_btnProvision setTitle:@"START" forState:UIControlStateNormal];
        flag = 1;
    }
}

#pragma mark get Current WiFi Name

-(NSString *)currentWifiSSID
{
    // Does not work on the simulator.
    NSString *ssid_str = nil;
    NSArray *ifs = (id)CNCopySupportedInterfaces();
    for (NSString *ifnam in ifs) {
        NSDictionary *info = (id)CNCopyCurrentNetworkInfo((CFStringRef)ifnam);
        NSLog(@"String %@", info);
        if (info[@"SSID"]) {
            ssid_str = info[@"SSID"];
            NSLog(@"ssid %@", ssid_str);
            for(int i = 0 ;i < [ssid_str length]; i++) {
                ssid[i] = [ssid_str characterAtIndex:i];
            }
            ssidLength = (unsigned)ssid_str.length;
            preamble[0] = 0x45;
            preamble[1] = 0x5a;
            preamble[2] = 0x50;
            preamble[3] = 0x52;
            preamble[4] = 0x32;
            preamble[5] = 0x32;
            
            txtNetworkName.text = ssid_str;
            NSString *savedValue = [[NSUserDefaults standardUserDefaults] stringForKey:ssid_str];
            if ([savedValue isEqualToString:@"NULL"]) {
                //do nothing
            } else {
                txtPassword.text = savedValue;
            }
        }
    }
    return ssid_str;
}

#pragma mark checkForWIFIConnection
-(BOOL)checkWifi
{
    Reachability* wifiReach = [Reachability reachabilityForLocalWiFi];

    NetworkStatus netStatus = [wifiReach currentReachabilityStatus];

    if (netStatus != ReachableViaWiFi) {
        [self showMessage:MARVELL_NO_WIFI withTag:70 withTarget:self];
        return NO;
    } else {
        self.strCurrentSSID = [self currentWifiSSID];
        if ([txtNetworkName.text isEqualToString:@""]) {
            isChecked = NO;
            [self showMessage:MARVELL_NO_WIFI withTag:70 withTarget:self];
            return NO;
        }
        txtPassword.hidden = NO;
        return YES;
    }
}


- (BOOL)checkWifiConnection
{
    Reachability* wifiReach = [Reachability reachabilityForLocalWiFi];

    NetworkStatus netStatus = [wifiReach currentReachabilityStatus];

    if (netStatus != ReachableViaWiFi) {
        isChecked = NO;
        [self showMessage:MARVELL_NO_WIFI withTag:70 withTarget:self];
        return NO;
    } else {
        self.strCurrentSSID = [self currentWifiSSID];
        if ([txtNetworkName.text isEqualToString:@""]) {
            isChecked = NO;
            [self showMessage:MARVELL_NO_NETWORK withTag:70 withTarget:self];
            return NO;
        }
        txtPassword.hidden = NO;
    }
    return YES;
}

#pragma mark TextField delegate

- (void)textFieldDidBeginEditing:(UITextField *)textField
{
    if (textField == txtPassword) {
        invalidPassphrase = 0;
        txtPassword.placeholder = @"";
    }
    if (textField == txtDeviceKey) {
        invalidKey = 0;
        txtDeviceKey.placeholder = @"";
    }
    if (textField == txtCustomData) {
        invalidCustomData = 0;
        txtCustomData.placeholder = @"";
    }
}

- (void)textFieldDidEndEditing:(UITextField *)textField {
    return;
}

- (BOOL)textField:(UITextField *)textField shouldChangeCharactersInRange:(NSRange)range replacementString:(NSString *)string
{
    return TRUE;
}


-(int) validatePassword:(UITextField *)textField
{
    int ret = 0;
    if (textField.text.length && textField.text.length < 8)
        ret = 1;
    if (textField.text.length > 64)
        ret = 1;
    return ret;
}

-(int) validateCustomData:(UITextField *)textField
{
    int ret = 0;
    NSCharacterSet *numbersOnly = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
    NSCharacterSet *characterSetFromTextField = [NSCharacterSet characterSetWithCharactersInString:textField.text];
    BOOL stringIsValid = [numbersOnly isSupersetOfSet:characterSetFromTextField];
    if (stringIsValid == 0)
        ret = 1;
    if ([textField.text length] % 2)
        ret = 1;
    if ([textField.text length] > 62)
        ret = 1;
    return ret;
}

-(int) validateDeviceKey:(UITextField *)textField
{
    return 0;
}



-(BOOL) textFieldShouldReturn:(UITextField *)textField
{
    // handle validations
    if (textField == txtPassword) {
        invalidPassphrase = [self validatePassword: textField];
    } else if (textField == txtCustomData) {
        invalidCustomData = [self validateCustomData: textField];
    } else if (textField == txtDeviceKey) {
        invalidKey = [self validateDeviceKey: textField];
    }

    // handle placeholders
    if (textField == txtPassword && [txtPassword.text isEqualToString:@""]) {
        txtPassword.placeholder = @"If required";
    } else if (textField == txtDeviceKey && [txtDeviceKey.text isEqualToString:@""]) {
        txtDeviceKey.placeholder = @"If required";
    } else if (textField == txtCustomData && [txtCustomData.text isEqualToString:@""]) {
        txtCustomData.placeholder = @"If required";
    }

    // update status
    if (!invalidKey && !invalidPassphrase && !invalidCustomData) {
        status.text = @"";
        self.btnProvision.enabled = YES;
    } else if (invalidKey) {
        self.btnProvision.enabled = NO;
        status.text = INVALID_KEY_LENGTH;
    } else if (invalidPassphrase){
        self.btnProvision.enabled = NO;
        status.text = INVALID_PASSPHRASE_LENGTH;
    } else if (invalidCustomData) {
        self.btnProvision.enabled = NO;
        status.text = INVALID_CUSTOM_DATA;
    }

    [textField resignFirstResponder];
    return YES;
}

#pragma mark ServerRequest Delegate

/* Function called on server request completion */
-(void)serverRequestDidFinishLoading:(ServerRequest *)server
{
    [server release];
}


-(void)serverRequest:(ServerRequest *)server didFailWithError:(NSError *)error{
    
    [server release];
}


- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)dealloc {
    [txtNetworkName release];
    [txtPassword release];
    [lblStatus release];
    [_btnProvision release];
    
    [_kScrollView release];
    [_lblPassphrase release];
    
    [_imgViewNetwork release];
    [_imgViewPassword release];
    [_lblNetwork release];
    [_viewBottom release];

    [_viewPassphrase release];
    [_imgViewDDown release];
    [super dealloc];
}
- (void)viewDidUnload {
    [self setKScrollView:nil];
    [self setLblPassphrase:nil];
    [self setImgViewNetwork:nil];
    [self setImgViewPassword:nil];
    [self setLblNetwork:nil];
    [self setViewBottom:nil];
    [self setViewPassphrase:nil];
    [self setViewPassphrase:nil];
    [self setImgViewDDown:nil];
    [super viewDidUnload];
}
@end
