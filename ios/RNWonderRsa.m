
#import "RNWonderRsa.h"
#import "XRSA.h"

@implementation RNWonderRsa

- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encrypt:(NSString *)content callback:(RCTResponseSenderBlock)callback) 
{
    XRSA *rsa = [[XRSA alloc] initWithPublicKey:[[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"]];
    if (rsa != nil) {
        NSString *encrypted = [rsa encryptToString:content];
        callback(@[[NSNull null], encrypted]);
    } else {
        callback(@[@"error"]);
    }
}

@end
  
