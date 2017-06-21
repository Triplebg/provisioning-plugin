//
//  StartProvisionViewController.h
//  Marvell
//
//  Copyright (c) 2014 Marvell. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "ServerRequestDelegate.h"
#import "TPKeyboardAvoidingScrollView.h"
#import <QuartzCore/QuartzCore.h>
#import <CoreText/CoreText.h>

@interface StartProvisionViewController : UIViewController <ServerRequestDelegate,UIAlertViewDelegate, NSNetServiceBrowserDelegate>
{
    IBOutlet UITextField *txtNetworkName;
    IBOutlet UITextField *txtPassword;
    IBOutlet UITextField *txtCustomData;
    IBOutlet UITextField *txtDeviceKey;
    IBOutlet UITextView *lblStatus;
    IBOutlet UILabel *status;
    BOOL isChecked;
    NSTimer *timer;
    UIAlertView *alertVw;
    NSTimer *timerMdns;
    unsigned char bssid[6];
    unsigned char preamble[6];
    Byte customData[32];
    Byte encryptedCustomData[32];
    char ssid[33];
    char passphrase[64];
    int TimerCount;
    int Mode;
    int passLen;
    int passLength;
    int customDataLen;
    int encryptedCustomDataLen;
    int invalidKey;
    int invalidPassphrase;
    int invalidCustomData;
    unsigned int ssidLength;
    unsigned long passCRC;
    unsigned long ssidCRC;
    unsigned long customDataCRC;
}

@property (retain, nonatomic) IBOutlet UIButton *btnProvision;
@property (retain, nonatomic) IBOutlet UIButton *btnRememberPassword;
@property (assign, nonatomic) NSInteger security;
@property (strong,atomic) NSMutableArray *services;
@property (assign, nonatomic) NSInteger state;
@property (assign, nonatomic) NSInteger substate;
@property (retain, nonatomic) NSString *strCurrentSSID;
@property (retain, nonatomic) IBOutlet TPKeyboardAvoidingScrollView *kScrollView;
@property (retain, nonatomic) IBOutlet UILabel *lblPassphrase;
@property (retain, nonatomic) IBOutlet UILabel *lblDeviceKey;
@property (retain, nonatomic) IBOutlet UIView *viewBottom;
@property (retain, nonatomic) IBOutlet UIImageView *imgViewNetwork;
@property (retain, nonatomic) IBOutlet UIImageView *imgViewDeviceKey;
@property (retain, nonatomic) IBOutlet UIImageView *imgViewPassword;
@property (retain, nonatomic) IBOutlet UILabel *lblNetwork;
@property (retain, nonatomic) IBOutlet UIView *viewPassphrase;
@property (retain, nonatomic) IBOutlet UIView *viewDeviceKey;
@property (retain, nonatomic) IBOutlet UIImageView *imgViewDDown;
@property (retain, nonatomic) IBOutlet UIImageView *imgProgressBar;
- (IBAction)OnProvisionClick:(id)sender;
- (IBAction)UnmaskPassword:(id)sender;
- (IBAction)RememberPassword:(id)sender;
- (IBAction)DisableRememberPassword:(id)sender;
@end
