#import "Compat.h"
#import "AppController.h"
#import "UIHelpers.h"
#include <signal.h>

/*
 * Startup is narrated with NSLog so a launch that "does nothing" can be diagnosed:
 * run  ./SecureShell.app/SecureShell  from a Terminal and see how far it gets.
 * Workspace throws a launched application's stderr away, so the same narration is also written
 * to ~/.SecureShell.trace when that file exists:   touch ~/.SecureShell.trace
 * then launch from Workspace and read the file.
 */
int main(int argc, char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    AppController *controller;
    int i;

    NSLog(@"SecureShell: starting");
    SSTrace("---- starting, argc=%d", argc);
    for (i = 0; i < argc; i++) SSTrace("  argv[%d] = %s", i, argv[i]);
    SSTrace("  cwd  = %s", SSCS([[NSFileManager defaultManager] currentDirectoryPath]));
    SSTrace("  HOME = %s", SSCS(NSHomeDirectory()));
    signal(SIGPIPE, SIG_IGN);                 /* a dropped connection must not kill the app */

    NS_DURING
        [NSApplication sharedApplication];
        NSLog(@"SecureShell: NSApplication created");
        SSTrace("NSApplication created");
        controller = [[AppController alloc] init];
        NSLog(@"SecureShell: controller created");
        SSTrace("controller created");
        [NSApp setDelegate:controller];
        [controller buildMenu];
        NSLog(@"SecureShell: menu built, entering the event loop");
        SSTrace("menu built, entering the event loop");
        [NSApp run];
        NSLog(@"SecureShell: event loop ended");
        SSTrace("event loop ended");
    NS_HANDLER
        NSLog(@"SecureShell: uncaught exception: %@ -- %@", [localException name], [localException reason]);
        SSTrace("uncaught exception: %s -- %s", SSCS([localException name]), SSCS([localException reason]));
    NS_ENDHANDLER

    [pool release];
    return 0;
}
