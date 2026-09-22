#import "Compat.h"
#import "AppController.h"
#import "UIHelpers.h"
#include <signal.h>
#include <stdlib.h>

/*
 * Startup is narrated with NSLog so a launch that "does nothing" can be diagnosed:
 * run  ./StepSSH.app/StepSSH  from a Terminal and see how far it gets.
 * Workspace throws a launched application's stderr away, so the same narration is also written
 * to ~/.StepSSH.trace when that file exists:   touch ~/.StepSSH.trace
 * then launch from Workspace and read the file.
 */
int main(int argc, char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    AppController *controller;
    int i;

    NSLog(@"StepSSH: starting");
    SSTrace("---- starting, argc=%d", argc);
    for (i = 0; i < argc; i++) SSTrace("  argv[%d] = %s", i, argv[i]);
    SSTrace("  cwd  = %s", SSCS([[NSFileManager defaultManager] currentDirectoryPath]));
    SSTrace("  NSHomeDirectory() = %s", SSCS(NSHomeDirectory()));
    /* NSHomeDirectory() may or may not consult $HOME; logging both settles which one, if either,
     * is wrong when they disagree (reported: both "/" when launched from Workspace). */
    SSTrace("  getenv(\"HOME\")   = %s", getenv("HOME") ? getenv("HOME") : "(not set)");
    SSTrace("  NSUserName()      = %s", SSCS(NSUserName()));
    signal(SIGPIPE, SIG_IGN);                 /* a dropped connection must not kill the app */

    NS_DURING
        [NSApplication sharedApplication];
        NSLog(@"StepSSH: NSApplication created");
        SSTrace("NSApplication created");
        controller = [[AppController alloc] init];
        NSLog(@"StepSSH: controller created");
        SSTrace("controller created");
        [NSApp setDelegate:controller];
        [controller buildMenu];
        NSLog(@"StepSSH: menu built, entering the event loop");
        SSTrace("menu built, entering the event loop");
        [NSApp run];
        NSLog(@"StepSSH: event loop ended");
        SSTrace("event loop ended");
    NS_HANDLER
        NSLog(@"StepSSH: uncaught exception: %@ -- %@", [localException name], [localException reason]);
        SSTrace("uncaught exception: %s -- %s", SSCS([localException name]), SSCS([localException reason]));
    NS_ENDHANDLER

    [pool release];
    return 0;
}
