#import "Compat.h"
#import "AppController.h"
#include <signal.h>

/*
 * Startup is narrated with NSLog so a launch that "does nothing" can be diagnosed:
 * run  ./SecureShell.app/SecureShell  from a Terminal and see how far it gets.
 * (From Workspace the same lines go to the Console.)
 */
int main(int argc, char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    AppController *controller;

    NSLog(@"SecureShell: starting");
    signal(SIGPIPE, SIG_IGN);                 /* a dropped connection must not kill the app */

    NS_DURING
        [NSApplication sharedApplication];
        NSLog(@"SecureShell: NSApplication created");
        controller = [[AppController alloc] init];
        NSLog(@"SecureShell: controller created");
        [NSApp setDelegate:controller];
        [controller buildMenu];
        NSLog(@"SecureShell: menu built, entering the event loop");
        [NSApp run];
        NSLog(@"SecureShell: event loop ended");
    NS_HANDLER
        NSLog(@"SecureShell: uncaught exception: %@ -- %@", [localException name], [localException reason]);
    NS_ENDHANDLER

    [pool release];
    return 0;
}
