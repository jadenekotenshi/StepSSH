#import "Compat.h"

/* Modal prompts.  Secrets are collected by SecretField, a tiny custom view
 * (not NSSecureTextField, which may not exist on OPENSTEP 4.2) that keeps the
 * text in a plain buffer we can wipe. */
@interface PromptPanel : NSObject
+ (char *)askSecret:(NSString *)prompt title:(NSString *)title;      /* malloc'd; caller wipes + frees. NULL = cancelled */
+ (NSString *)askText:(NSString *)prompt title:(NSString *)title;   /* nil = cancelled */
+ (NSString *)askText:(NSString *)prompt title:(NSString *)title initial:(NSString *)initial;
@end
