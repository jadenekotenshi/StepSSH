#import "SFTPBrowser.h"
#import "SSHSession.h"
#import "UIHelpers.h"
#import "PromptPanel.h"
#include "sftp.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#ifdef OPENSTEP
/* On this system <dirent.h> is found but does not typedef DIR (gcc: "undefined type, found DIR") --
 * the classic BSD header, which some NeXT-lineage libcs keep the real declarations in, still might.
 * Safe to add unconditionally: if <dirent.h> already declared everything, this is just a harmless
 * second inclusion (header guards make it a no-op); it is not removing or replacing anything. */
#include <sys/dir.h>
#endif
#include <errno.h>
#include "oscompat.h"

#ifdef OPENSTEP
/* readdir() pairs with <sys/dir.h>'s DIR here and returns struct direct * (the classic BSD name),
 * not struct dirent * (the POSIX name this file otherwise assumes, and what the host build gets) --
 * both have a d_name field, which is all this file uses. */
typedef struct direct ss_dirent;
#else
typedef struct dirent ss_dirent;
#endif

/* ------------------------------------------------------------------ */
/* a plain progress bar                                                */

@interface ProgressBar : NSView
{
    float fraction;
}
- (void)setFraction:(float)f;
@end

@implementation ProgressBar
- (void)setFraction:(float)f
{
    if (f < 0.0) f = 0.0;
    if (f > 1.0) f = 1.0;
    if (f != fraction) { fraction = f; [self setNeedsDisplay:YES]; }
}
- (BOOL)isOpaque { return YES; }
- (void)drawRect:(NSRect)rect
{
    NSRect b = [self bounds], bar;
    [[NSColor whiteColor] set];
    NSRectFill(b);
    [[NSColor blackColor] set];
    NSFrameRect(b);
    bar = NSInsetRect(b, 2, 2);
    bar.size.width *= fraction;
    [[NSColor darkGrayColor] set];
    NSRectFill(bar);
}
@end

@interface SFTPBrowser (Private)
- (void)buildWindow;
- (void)setStatus:(NSString *)s;
- (void)setControlsEnabled;
- (void)navigate:(NSString *)path;
- (void)listResolved:(NSString *)canonical;
- (void)listFinished:(sftp_dirlist *)d;
- (void)navFailed:(NSString *)message;
- (void)runNextJob;
- (void)stepDone:(BOOL)ok message:(NSString *)msg;
- (void)transferChanged:(sftp_xfer *)x;
- (void)finishTransfer:(sftp_xfer *)x;
- (void)failJobs:(NSString *)message;
- (NSArray *)selectedEntries;
- (NSString *)remoteJoin:(NSString *)name;
- (sftp *)core;
- (void)kick;
- (void)walkListFinished:(sftp_dirlist *)d;
- (void)walkMkdirDone;
- (void)queueUploadsOfPaths:(NSArray *)paths;
- (void)droppedFiles:(NSArray *)paths;
@end

/* ------------------------------------------------------------------ */
/* the file listing table: also a drag destination, for dropping files or folders from Workspace's  */
/* File Viewer to upload them.  registerForDraggedTypes: and the NSDraggingDestination methods below */
/* are original OpenStep API (present since NeXTSTEP); NSTableView's own drag-source and data-source  */
/* hooks (for dragging rows out, or reordering them) are unrelated and untouched. Drag-OUT to         */
/* download is not implemented: it would need "promised" files (Mac OS X 10.2+; see droppedFiles:).   */

@interface SFTPTableView : NSTableView
{
    id owner;                    /* not retained, mirrors TerminalView's delegate: the SFTPBrowser */
}
- (void)setOwner:(id)anObject;
@end

@implementation SFTPTableView
- (id)initWithFrame:(NSRect)frame
{
    self = [super initWithFrame:frame];
    if (self) [self registerForDraggedTypes:[NSArray arrayWithObject:NSFilenamesPboardType]];
    return self;
}
- (void)setOwner:(id)anObject { owner = anObject; }

- (SSDragOp)draggingEntered:(id <NSDraggingInfo>)sender
{
    NSPasteboard *pb = [sender draggingPasteboard];
    if (![pb availableTypeFromArray:[NSArray arrayWithObject:NSFilenamesPboardType]]) return NSDragOperationNone;
    if (owner && ![owner isReady]) return NSDragOperationNone;      /* not connected: nothing to drop onto */
    return NSDragOperationCopy;
}
- (SSDragOp)draggingUpdated:(id <NSDraggingInfo>)sender { return [self draggingEntered:sender]; }
- (BOOL)prepareForDragOperation:(id <NSDraggingInfo>)sender { return YES; }
- (BOOL)performDragOperation:(id <NSDraggingInfo>)sender
{
    NSArray *paths = [[sender draggingPasteboard] propertyListForType:NSFilenamesPboardType];
    if (![paths count]) return NO;
    if (owner) [owner droppedFiles:paths];
    return YES;
}
- (void)concludeDragOperation:(id <NSDraggingInfo>)sender { }
@end

@implementation SFTPEntry
- (void)dealloc { [name release]; [super dealloc]; }
- (NSComparisonResult)compareToEntry:(SFTPEntry *)other
{
    if (isDir != other->isDir) return isDir ? NSOrderedAscending : NSOrderedDescending;
    return [name caseInsensitiveCompare:other->name];
}
@end

/* ------------------------------------------------------------------ */

/* ---- C callbacks: sftp.c calls these from inside sftp_input() ---- */

static void cb_realpath(sftp *s, const sftp_response *r, void *ctx)
{
    SFTPBrowser *b = (SFTPBrowser *)ctx;
    if (r->type == SFTP_R_NAME && r->nnames > 0) [b listResolved:ui_string_from_utf8(r->names[0].name)];
    else [b navFailed:r->type == SFTP_R_STATUS ? ui_string_from_utf8(r->message) : @"unexpected reply"];
}

static void cb_list(sftp_dirlist *d, void *ctx) { [(SFTPBrowser *)ctx listFinished:d]; }

static void cb_step(sftp *s, const sftp_response *r, void *ctx)
{
    BOOL ok = !(r->type == SFTP_R_STATUS && r->status != SFTP_OK);
    [(SFTPBrowser *)ctx stepDone:ok message:ok ? @"" : ui_string_from_utf8(r->message)];
}

static void cb_xfer(sftp_xfer *x, void *ctx) { [(SFTPBrowser *)ctx transferChanged:x]; }

/* Recursive transfer: a directory listing (download side) or a mkdir reply (upload side) for a
 * "walkdir"/"walkupload" job in progress.  Distinct from cb_list/cb_step, which drive the browser's
 * own visible listing and the plain single-step jobs -- these must not touch either. */
static void cb_walklist(sftp_dirlist *d, void *ctx) { [(SFTPBrowser *)ctx walkListFinished:d]; }
static void cb_walkmkdir(sftp *s, const sftp_response *r, void *ctx) { [(SFTPBrowser *)ctx walkMkdirDone]; }

@implementation SFTPBrowser

- (id)initWithSession:(SSHSession *)s host:(NSString *)h user:(NSString *)u
{
    self = [super init];
    if (!self) return nil;
    session = s;
    host = [h copy]; user = [u copy];
    entries = [[NSMutableArray alloc] init];
    jobs = [[NSMutableArray alloc] init];
    cwd = [@"" retain];
    [self buildWindow];
    return self;
}

- (void)dealloc
{
    [window setDelegate:nil];
    [host release]; [user release]; [window release]; [entries release]; [jobs release];
    [cwd release]; [wanted release]; [xlocal release];
    [walkRemote release]; [walkLocal release];
    [super dealloc];
}

- (NSWindow *)window { return window; }
- (BOOL)isBusy { return busy || listing || [jobs count] > 0; }
- (BOOL)isReady { return ready && !dead; }
- (int)entryCount { return (int)[entries count]; }
- (SFTPEntry *)entryAtIndex:(int)i { return [entries objectAtIndex:i]; }
- (NSString *)currentPath { return cwd; }
- (NSString *)statusText { return [statusLabel stringValue]; }
- (sftp *)core { return dead ? NULL : (sftp *)[session sftpCore]; }
- (void)kick { [session sftpKick]; }

/* ---------------------------------------------------------------- */
/* the window                                                       */

- (void)buildWindow
{
    static float offset = 0.0;
    NSView *c;
    NSScrollView *scroll;
    NSTableColumn *col;
    NSRect scr = [[NSScreen mainScreen] frame];
    int i;
    NSString *colIdent[4], *colTitle[4];      /* filled in at run time: not a static initializer of
                                                 constant strings, which old gcc may reject */
    float colWidth[4];

    colIdent[0] = @"name";  colTitle[0] = @"Name";     colWidth[0] = 280;
    colIdent[1] = @"size";  colTitle[1] = @"Size";     colWidth[1] = 90;
    colIdent[2] = @"mtime"; colTitle[2] = @"Modified"; colWidth[2] = 130;
    colIdent[3] = @"mode";  colTitle[3] = @"Mode";     colWidth[3] = 100;

    window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 660, 440)
                                         styleMask:(NSTitledWindowMask | NSClosableWindowMask |
                                                    NSMiniaturizableWindowMask | NSResizableWindowMask)
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    [window setReleasedWhenClosed:NO];
    [window setDelegate:(id)self];
    [window setMinSize:NSMakeSize(520, 260)];
    [window setTitle:[NSString stringWithFormat:@"Files - %@@%@", user, host]];
    c = [window contentView];

    upBtn = ui_button(@"Up", NSMakeRect(8, 408, 56, 26), self, @selector(goUp:));
    refreshBtn = ui_button(@"Refresh", NSMakeRect(68, 408, 72, 26), self, @selector(refresh:));
    pathField = ui_field(NSMakeRect(148, 410, 504, 22));
    [pathField setTarget:self];
    [pathField setAction:@selector(pathEntered:)];
    [upBtn setAutoresizingMask:NSViewMinYMargin];
    [refreshBtn setAutoresizingMask:NSViewMinYMargin];
    [pathField setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
    [c addSubview:upBtn]; [c addSubview:refreshBtn]; [c addSubview:pathField];

    table = [[[SFTPTableView alloc] initWithFrame:NSMakeRect(0, 0, 640, 300)] autorelease];
    [(SFTPTableView *)table setOwner:self];
    for (i = 0; i < 4; i++) {
        col = [[[NSTableColumn alloc] initWithIdentifier:colIdent[i]] autorelease];
        [[col headerCell] setStringValue:colTitle[i]];
        [col setWidth:colWidth[i]];
        [col setEditable:NO];
        if (i == 1) [[col dataCell] setAlignment:NSRightTextAlignment];
        [table addTableColumn:col];
    }
    [table setDataSource:(id)self];
    [table setAllowsMultipleSelection:YES];
    [table setTarget:self];
    [table setDoubleAction:@selector(rowDoubleClicked:)];
    scroll = [[[NSScrollView alloc] initWithFrame:NSMakeRect(8, 84, 644, 316)] autorelease];
    [scroll setHasVerticalScroller:YES];
    [scroll setBorderType:NSBezelBorder];
    [scroll setDocumentView:table];
    [scroll setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    [c addSubview:scroll];

    statusLabel = ui_label(@"", NSMakeRect(8, 56, 560, 20));
    [statusLabel setAutoresizingMask:(NSViewWidthSizable | NSViewMaxYMargin)];
    [c addSubview:statusLabel];
    meter = [[[ProgressBar alloc] initWithFrame:NSMakeRect(8, 40, 480, 12)] autorelease];
    [meter setAutoresizingMask:NSViewMaxYMargin];
    [c addSubview:meter];
    cancelBtn = ui_button(@"Cancel", NSMakeRect(496, 34, 70, 24), self, @selector(cancelTransfer:));
    [cancelBtn setAutoresizingMask:NSViewMaxYMargin];
    [c addSubview:cancelBtn];

    downBtn = ui_button(@"Download", NSMakeRect(8, 8, 92, 26), self, @selector(download:));
    upBtnLoad = ui_button(@"Upload", NSMakeRect(104, 8, 92, 26), self, @selector(upload:));
    mkdirBtn = ui_button(@"New Folder", NSMakeRect(200, 8, 100, 26), self, @selector(newFolder:));
    renameBtn = ui_button(@"Rename", NSMakeRect(304, 8, 84, 26), self, @selector(rename:));
    deleteBtn = ui_button(@"Delete", NSMakeRect(392, 8, 84, 26), self, @selector(delete:));
    { NSButton *bs[5]; int k; bs[0] = downBtn; bs[1] = upBtnLoad; bs[2] = mkdirBtn; bs[3] = renameBtn; bs[4] = deleteBtn;
      for (k = 0; k < 5; k++) { [bs[k] setAutoresizingMask:NSViewMaxYMargin]; [c addSubview:bs[k]]; } }

    [window setFrameTopLeftPoint:NSMakePoint(scr.origin.x + 120 + offset, NSMaxY(scr) - 80 - offset)];
    offset += 24.0;
    if (offset > 240.0) offset = 0.0;
    [self setControlsEnabled];
}

- (void)show
{
    [window makeKeyAndOrderFront:nil];
}

- (void)closeWindow
{
    [window setDelegate:nil];
    [window orderOut:nil];
}

- (void)setStatus:(NSString *)s { [statusLabel setStringValue:s]; }

- (void)setControlsEnabled
{
    BOOL on = ready && !dead;
    [upBtn setEnabled:on]; [refreshBtn setEnabled:on]; [downBtn setEnabled:on]; [upBtnLoad setEnabled:on];
    [mkdirBtn setEnabled:on]; [renameBtn setEnabled:on]; [deleteBtn setEnabled:on];
    [pathField setEditable:on];
    [cancelBtn setEnabled:busy && !dead];
}

/* ---------------------------------------------------------------- */
/* driven by the session                                            */

- (void)sftpReady
{
    ready = YES;
    [self setControlsEnabled];
    [self setStatus:@"Connected."];
    [self navigate:@"."];
}

- (void)sftpFailed:(NSString *)message
{
    dead = YES;
    [self setControlsEnabled];
    [self setStatus:message];
    NSRunAlertPanel(@"File browser", @"%@", @"OK", nil, nil, message);
}

- (void)sessionEnded
{
    if (dead) return;
    dead = YES;
    if (xfile) { fclose(xfile); xfile = NULL; }
    [self setControlsEnabled];
    [self setStatus:@"Disconnected."];
}

/* ---------------------------------------------------------------- */
/* navigation and listing                                           */

- (void)goTo:(NSString *)path { [self navigate:path]; }

- (void)navigate:(NSString *)path
{
    sftp *core = [self core];
    if (!core || !ready) return;
    [wanted release];
    wanted = [path retain];
    listing = YES;
    [self setStatus:[NSString stringWithFormat:@"Reading %@ ...", path]];
    if (!sftp_realpath(core, UI_CPATH(path), cb_realpath, self)) { listing = NO; [self setStatus:@"Cannot send request."]; return; }
    [self kick];
}

- (void)listResolved:(NSString *)canonical
{
    sftp *core = [self core];
    [wanted release];
    wanted = [canonical retain];
    if (!core || !sftp_list(core, UI_CPATH(canonical), cb_list, self)) { listing = NO; [self setStatus:@"Cannot list the directory."]; return; }
    [self kick];
}

- (void)listFinished:(sftp_dirlist *)d
{
    int i, n;
    listing = NO;
    if (!sftp_dirlist_ok(d)) {
        [self setStatus:[NSString stringWithFormat:@"%@: %@", wanted, ui_string_from_utf8(sftp_dirlist_error(d))]];
        [pathField setStringValue:cwd];
        sftp_dirlist_free(d);
        if ([jobs count] && !busy) [self runNextJob];
        return;
    }
    [entries removeAllObjects];
    n = sftp_dirlist_count(d);
    for (i = 0; i < n; i++) {
        const sftp_name *nm = sftp_dirlist_entry(d, i);
        SFTPEntry *e = [[[SFTPEntry alloc] init] autorelease];
        e->name = [ui_string_from_utf8(nm->name) retain];
        e->perms = nm->attrs.perms;
        e->isDir = SFTP_S_ISDIR(nm->attrs.perms) ? YES : NO;
        e->isLink = SFTP_S_ISLNK(nm->attrs.perms) ? YES : NO;
        e->size = (nm->attrs.flags & SFTP_ATTR_SIZE) ? nm->attrs.size : 0;
        e->mtime = nm->attrs.mtime;
        [entries addObject:e];
    }
    sftp_dirlist_free(d);
    [entries sortUsingSelector:@selector(compareToEntry:)];
    [cwd release];
    cwd = [wanted retain];
    dirty = NO;
    [pathField setStringValue:cwd];
    [table reloadData];
    [table deselectAll:nil];
    [self setStatus:[NSString stringWithFormat:@"%d item%s", (int)[entries count], [entries count] == 1 ? "" : "s"]];
    if ([jobs count] && !busy) [self runNextJob];
}

- (void)navFailed:(NSString *)message
{
    listing = NO;
    [self setStatus:[NSString stringWithFormat:@"%@: %@", wanted, message]];
    [pathField setStringValue:cwd];
}

- (NSString *)remoteJoin:(NSString *)name
{
    return [cwd stringByAppendingPathComponent:name];
}

- (void)goUp:(id)sender
{
    if ([cwd length] && ![cwd isEqual:@"/"]) [self navigate:[cwd stringByDeletingLastPathComponent]];
}

- (void)refresh:(id)sender { if ([cwd length]) [self navigate:cwd]; }

- (void)pathEntered:(id)sender
{
    NSString *p = ui_trim([pathField stringValue]);
    if ([p length]) [self navigate:p];
}

- (void)rowDoubleClicked:(id)sender
{
    int row = [table clickedRow];
    SFTPEntry *e;
    if (row < 0 || row >= (int)[entries count]) return;
    e = [entries objectAtIndex:row];
    if (e->isDir) [self navigate:[self remoteJoin:e->name]];
    else [self download:nil];
}

/* ---------------------------------------------------------------- */
/* table data source                                                */

- (int)numberOfRowsInTableView:(NSTableView *)tv { return (int)[entries count]; }

- (id)tableView:(NSTableView *)tv objectValueForTableColumn:(NSTableColumn *)col row:(int)row
{
    SFTPEntry *e;
    NSString *ident = [col identifier];
    if (row < 0 || row >= (int)[entries count]) return @"";
    e = [entries objectAtIndex:row];
    if ([ident isEqual:@"name"]) return e->isDir ? [e->name stringByAppendingString:@"/"] : e->name;
    if ([ident isEqual:@"size"]) return e->isDir ? @"" : ui_format_size(e->size);
    if ([ident isEqual:@"mtime"]) return ui_format_time(e->mtime);
    if ([ident isEqual:@"mode"]) return ui_format_mode(e->perms);
    return @"";
}

- (NSArray *)selectedEntries
{
    NSMutableArray *out = [NSMutableArray array];
    NSEnumerator *en = [table selectedRowEnumerator];
    id n;
    while ((n = [en nextObject])) {
        int r = [n intValue];
        if (r >= 0 && r < (int)[entries count]) [out addObject:[entries objectAtIndex:r]];
    }
    return out;
}

/* ---------------------------------------------------------------- */
/* queueing operations                                              */

- (void)queueJob:(NSString *)op a:(NSString *)a b:(NSString *)b size:(unsigned long long)size
{
    NSMutableDictionary *j = [NSMutableDictionary dictionary];
    [j setObject:op forKey:@"op"];
    if (a) [j setObject:a forKey:@"a"];
    if (b) [j setObject:b forKey:@"b"];
    [j setObject:[NSNumber numberWithUnsignedLong:(unsigned long)size] forKey:@"size"];
    [jobs addObject:j];
    [self runNextJob];
}

- (void)queueUploadOfLocal:(NSString *)local toRemote:(NSString *)remote { [self queueJob:@"put" a:local b:remote size:0]; }
- (void)queueDownloadOfRemote:(NSString *)remote toLocal:(NSString *)local size:(unsigned long long)size
{ [self queueJob:@"get" a:remote b:local size:size]; }
- (void)queueWalkDownloadOfRemote:(NSString *)remote toLocal:(NSString *)local { [self queueJob:@"walkdir" a:remote b:local size:0]; }
- (void)queueWalkUploadOfLocal:(NSString *)local toRemote:(NSString *)remote { [self queueJob:@"walkupload" a:local b:remote size:0]; }
- (void)queueMkdir:(NSString *)remote { [self queueJob:@"mkdir" a:remote b:nil size:0]; }
- (void)queueRemove:(NSString *)remote directory:(BOOL)isDir { [self queueJob:(isDir ? @"rmdir" : @"rm") a:remote b:nil size:0]; }
- (void)queueRename:(NSString *)from to:(NSString *)to { [self queueJob:@"mv" a:from b:to size:0]; }

- (void)runNextJob
{
    sftp *core = [self core];
    while (!busy && [jobs count] && core && ready) {
        NSDictionary *job = [[[jobs objectAtIndex:0] retain] autorelease];
        NSString *op = [job objectForKey:@"op"], *a = [job objectForKey:@"a"], *b = [job objectForKey:@"b"];
        unsigned long size = [[job objectForKey:@"size"] unsignedLongValue];
        [jobs removeObjectAtIndex:0];

        if ([op isEqual:@"get"]) {
            xfile = fopen([b cString], "wb");
            if (!xfile) { [self failJobs:[NSString stringWithFormat:@"Cannot create %@", b]]; return; }
            xfer = sftp_download(core, UI_CPATH(a), xfile, size, cb_xfer, self);
            if (!xfer) { fclose(xfile); xfile = NULL; [self failJobs:@"Cannot start the download."]; return; }
            [xlocal release]; xlocal = [b retain]; xisDownload = YES;
            busy = YES; fraction = 0;
            [self setStatus:[NSString stringWithFormat:@"Downloading %@ ...", [a lastPathComponent]]];
        } else if ([op isEqual:@"put"]) {
            struct stat st;
            if (stat([a cString], &st) != 0 || (xfile = fopen([a cString], "rb")) == NULL) {
                [self failJobs:[NSString stringWithFormat:@"Cannot read %@", a]];
                return;
            }
            xfer = sftp_upload(core, UI_CPATH(b), xfile, (unsigned)(st.st_mode & 0777), (unsigned long long)st.st_size, cb_xfer, self);
            if (!xfer) { fclose(xfile); xfile = NULL; [self failJobs:@"Cannot start the upload."]; return; }
            [xlocal release]; xlocal = nil; xisDownload = NO;
            busy = YES; fraction = 0;
            [self setStatus:[NSString stringWithFormat:@"Uploading %@ ...", [a lastPathComponent]]];
        } else if ([op isEqual:@"walkdir"]) {
            /* The parent directory is guaranteed to exist already: a "walkdir" job for a
             * subdirectory is only ever queued after its parent's own walkdir step has both run
             * (creating the parent locally) and listed the remote side, so a plain, non-recursive
             * mkdir is always enough here -- never "mkdir -p", which OPENSTEP does not have. */
            BOOL isDir = NO;
            if (![[NSFileManager defaultManager] fileExistsAtPath:b isDirectory:&isDir] || !isDir) {
                if (mkdir([b cString], 0755) != 0 && errno != EEXIST) {
                    [self failJobs:[NSString stringWithFormat:@"Cannot create %@", b]];
                    return;
                }
            }
            [walkRemote release]; walkRemote = [a retain];
            [walkLocal release]; walkLocal = [b retain];
            if (!sftp_list(core, UI_CPATH(a), cb_walklist, self)) { [self failJobs:@"Cannot list the directory."]; return; }
            busy = YES;
            [self setStatus:[NSString stringWithFormat:@"Reading %@ ...", a]];
        } else {
            u32 rid = 0;
            if ([op isEqual:@"mkdir"]) rid = sftp_mkdir(core, UI_CPATH(a), 0755, cb_step, self);
            else if ([op isEqual:@"rmdir"]) rid = sftp_rmdir(core, UI_CPATH(a), cb_step, self);
            else if ([op isEqual:@"rm"]) rid = sftp_remove(core, UI_CPATH(a), cb_step, self);
            else if ([op isEqual:@"mv"]) rid = sftp_rename(core, UI_CPATH(a), UI_CPATH(b), cb_step, self);
            else if ([op isEqual:@"walkupload"]) {
                /* Same reasoning as "walkdir", mirrored: the remote parent directory is already
                 * there, so one plain, non-recursive mkdir suffices.  Its result is not checked --
                 * SFTP v3 has no distinct "already exists" status, and any real problem (e.g.
                 * permission denied) surfaces on the first file uploaded into it regardless. */
                [walkRemote release]; walkRemote = [b retain];
                [walkLocal release]; walkLocal = [a retain];
                rid = sftp_mkdir(core, UI_CPATH(b), 0755, cb_walkmkdir, self);
            }
            if (!rid) { [self failJobs:@"Cannot send the request."]; return; }
            busy = YES;
        }
        [self setControlsEnabled];
        [self kick];
        return;
    }
    if (!busy && ![jobs count] && dirty && !listing && ready && !dead) [self refresh:nil];
}

- (void)failJobs:(NSString *)message
{
    [jobs removeAllObjects];
    busy = NO;
    [self setControlsEnabled];
    [self setStatus:message];
    NSRunAlertPanel(@"File browser", @"%@", @"OK", nil, nil, message);
}

- (void)stepDone:(BOOL)ok message:(NSString *)msg
{
    busy = NO;
    dirty = YES;
    [self setControlsEnabled];
    if (!ok) { [self failJobs:msg]; return; }
    [self runNextJob];
}

- (void)transferChanged:(sftp_xfer *)x
{
    if (sftp_xfer_state(x) == SFTP_XFER_RUNNING) {
        unsigned long long tot = sftp_xfer_total(x), done = sftp_xfer_bytes(x);
        fraction = tot ? (float)((double)done / (double)tot) : 0.0;
        [(ProgressBar *)meter setFraction:fraction];
        [self setStatus:[NSString stringWithFormat:@"%@ %@ of %@",
                         xisDownload ? @"Downloading:" : @"Uploading:", ui_format_size(done),
                         tot ? ui_format_size(tot) : @"?"]];
        return;
    }
    [self finishTransfer:x];
}

- (void)finishTransfer:(sftp_xfer *)x
{
    int state = sftp_xfer_state(x);
    NSString *err = state == SFTP_XFER_FAILED ? ui_string_from_utf8(sftp_xfer_error(x)) : nil;
    unsigned long long done = sftp_xfer_bytes(x);
    if (xfile) { fclose(xfile); xfile = NULL; }
    if (xisDownload && xlocal && state != SFTP_XFER_DONE) remove([xlocal cString]);     /* no half-files */
    xfer = NULL;
    sftp_xfer_free(x);
    busy = NO;
    dirty = YES;
    [(ProgressBar *)meter setFraction:0];
    [self setControlsEnabled];
    if (state == SFTP_XFER_FAILED) {
        if (!dead) [self failJobs:err];
        return;
    }
    if (state == SFTP_XFER_CANCELLED) {
        [jobs removeAllObjects];
        [self setStatus:@"Transfer cancelled."];
        if (!dead) [self refresh:nil];
        return;
    }
    [self setStatus:[NSString stringWithFormat:@"Transferred %@.", ui_format_size(done)]];
    [self runNextJob];
}

- (void)cancelTransfer:(id)sender
{
    [jobs removeAllObjects];
    if (xfer) sftp_xfer_cancel((sftp_xfer *)xfer);
    if (busy && !xfer) walkCancelled = YES;     /* a walkdir/walkupload step's reply is still in flight */
}

/* ---------------------------------------------------------------- */
/* recursive transfers: called back once the request for a "walkdir" or "walkupload" step         */
/* (queued in runNextJob) replies -- everything this directory contains is queued right behind     */
/* whatever else is queued, so this subtree finishes before its next sibling.                      */

- (void)walkListFinished:(sftp_dirlist *)d
{
    NSString *remoteBase = [walkRemote retain], *localBase = [walkLocal retain];
    int i, n, insertAt = 0;
    busy = NO;
    if (walkCancelled) {
        walkCancelled = NO;
        sftp_dirlist_free(d);
        [remoteBase release]; [localBase release];
        [self setControlsEnabled];
        [self runNextJob];
        return;
    }
    if (!sftp_dirlist_ok(d)) {
        NSString *msg = [NSString stringWithFormat:@"%@: %@", remoteBase, ui_string_from_utf8(sftp_dirlist_error(d))];
        sftp_dirlist_free(d);
        [remoteBase release]; [localBase release];
        [self failJobs:msg];
        return;
    }
    n = sftp_dirlist_count(d);
    for (i = 0; i < n; i++) {
        const sftp_name *nm = sftp_dirlist_entry(d, i);
        NSString *name = ui_string_from_utf8(nm->name);
        NSString *rp, *lp;
        NSMutableDictionary *j;
        if ([name isEqual:@"."] || [name isEqual:@".."]) continue;
        rp = [remoteBase stringByAppendingPathComponent:name];
        lp = [localBase stringByAppendingPathComponent:name];
        j = [NSMutableDictionary dictionary];
        if (SFTP_S_ISDIR(nm->attrs.perms)) {
            [j setObject:@"walkdir" forKey:@"op"]; [j setObject:rp forKey:@"a"]; [j setObject:lp forKey:@"b"];
        } else if (!SFTP_S_ISLNK(nm->attrs.perms)) {                 /* symlinks are not followed */
            unsigned long long size = (nm->attrs.flags & SFTP_ATTR_SIZE) ? nm->attrs.size : 0;
            [j setObject:@"get" forKey:@"op"]; [j setObject:rp forKey:@"a"]; [j setObject:lp forKey:@"b"];
            [j setObject:[NSNumber numberWithUnsignedLong:(unsigned long)size] forKey:@"size"];
        } else {
            continue;
        }
        [jobs insertObject:j atIndex:insertAt++];
    }
    sftp_dirlist_free(d);
    [remoteBase release]; [localBase release];
    [self setControlsEnabled];
    [self runNextJob];
}

- (void)walkMkdirDone
{
    NSString *localBase = [walkLocal retain], *remoteBase = [walkRemote retain];
    DIR *dp;
    ss_dirent *de;
    int insertAt = 0;
    busy = NO;
    if (walkCancelled) {
        walkCancelled = NO;
        [localBase release]; [remoteBase release];
        [self setControlsEnabled];
        [self runNextJob];
        return;
    }
    dp = opendir([localBase cString]);
    if (!dp) {
        [localBase release]; [remoteBase release];
        [self failJobs:[NSString stringWithFormat:@"Cannot read %@", localBase]];
        return;
    }
    while ((de = readdir(dp)) != NULL) {
        NSString *name, *lp, *rp;
        struct stat st;
        NSMutableDictionary *j;
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        name = ui_string_from_utf8(de->d_name);
        lp = [localBase stringByAppendingPathComponent:name];
        rp = [remoteBase stringByAppendingPathComponent:name];
        if (stat([lp cString], &st) != 0) continue;                   /* vanished, or unreadable: skip it */
        j = [NSMutableDictionary dictionary];
        if (SFTP_S_ISDIR((unsigned long)st.st_mode)) {
            [j setObject:@"walkupload" forKey:@"op"]; [j setObject:lp forKey:@"a"]; [j setObject:rp forKey:@"b"];
        } else if (SFTP_S_ISREG((unsigned long)st.st_mode)) {
            [j setObject:@"put" forKey:@"op"]; [j setObject:lp forKey:@"a"]; [j setObject:rp forKey:@"b"];
        } else {
            continue;                                                 /* devices, fifos, etc.: not uploaded */
        }
        [jobs insertObject:j atIndex:insertAt++];
    }
    closedir(dp);
    [localBase release]; [remoteBase release];
    [self setControlsEnabled];
    [self runNextJob];
}

/* ---------------------------------------------------------------- */
/* buttons                                                          */

- (void)download:(id)sender
{
    NSArray *sel = [self selectedEntries];
    NSSavePanel *panel;
    NSString *dir, *target;
    int i;
    BOOL anyDirs = NO;

    if ([sel count] == 0) { NSRunAlertPanel(@"Download", @"Select one or more items first.", @"OK", nil, nil); return; }
    for (i = 0; i < (int)[sel count]; i++) if (((SFTPEntry *)[sel objectAtIndex:i])->isDir) anyDirs = YES;

    if ([sel count] == 1 && !anyDirs) {                     /* one plain file: pick its exact destination name */
        SFTPEntry *e = [sel objectAtIndex:0];
        panel = [NSSavePanel savePanel];
        [panel setTitle:@"Download"];
        if ([panel runModalForDirectory:NSHomeDirectory() file:e->name] != NSOKButton) return;
        [self queueDownloadOfRemote:[self remoteJoin:e->name] toLocal:[panel filename] size:e->size];
        return;
    }

    /* several items, or at least one folder: pick a destination folder (the NSSavePanel-on-a-
     * placeholder-name trick, same as before -- runModalForDirectory:file: is what is confirmed
     * working on OPENSTEP; NSOpenPanel's own -setCanChooseDirectories: is used for uploads below,
     * since only a folder can be chosen there and it is unconfirmed there too). */
    panel = [NSSavePanel savePanel];
    [panel setTitle:@"Choose the destination folder, then click Save"];
    if ([panel runModalForDirectory:NSHomeDirectory() file:@"(folder)"] != NSOKButton) return;
    dir = [[panel filename] stringByDeletingLastPathComponent];
    for (i = 0; i < (int)[sel count]; i++) {
        SFTPEntry *e = [sel objectAtIndex:i];
        target = [dir stringByAppendingPathComponent:e->name];
        if (e->isDir) {
            [self queueWalkDownloadOfRemote:[self remoteJoin:e->name] toLocal:target];
            continue;
        }
        if ([[NSFileManager defaultManager] fileExistsAtPath:target] &&
            NSRunAlertPanel(@"Replace file?", @"%@ already exists.", @"Replace", @"Skip", nil, target) != NSAlertDefaultReturn)
            continue;
        [self queueDownloadOfRemote:[self remoteJoin:e->name] toLocal:target size:e->size];
    }
}

- (void)queueUploadsOfPaths:(NSArray *)paths
{
    int i, j;
    for (i = 0; i < (int)[paths count]; i++) {
        NSString *local = [paths objectAtIndex:i], *leaf = [local lastPathComponent];
        struct stat st;
        BOOL exists = NO, isDir;
        for (j = 0; j < (int)[entries count]; j++)
            if ([((SFTPEntry *)[entries objectAtIndex:j])->name isEqual:leaf]) exists = YES;
        isDir = (stat([local cString], &st) == 0 && SFTP_S_ISDIR((unsigned long)st.st_mode));
        if (exists && NSRunAlertPanel(@"Replace?",
                isDir ? @"A folder named %@ already exists on the server. Its contents will be merged."
                      : @"%@ already exists on the server.",
                @"Replace", @"Skip", nil, leaf) != NSAlertDefaultReturn)
            continue;
        if (isDir) [self queueWalkUploadOfLocal:local toRemote:[self remoteJoin:leaf]];
        else [self queueUploadOfLocal:local toRemote:[self remoteJoin:leaf]];
    }
}

- (void)upload:(id)sender
{
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setAllowsMultipleSelection:YES];
    [panel setCanChooseDirectories:YES];        /* part of the OpenStep spec's NSOpenPanel, not a later addition */
    [panel setTitle:@"Upload"];
    if ([panel runModalForDirectory:NSHomeDirectory() file:nil types:nil] != NSOKButton) return;
    [self queueUploadsOfPaths:[panel filenames]];
}

/* Dropping files or folders from Workspace's File Viewer onto the table -- see SFTPTableView below.
 * Only the upload direction: dragging OUT to download would need OPENSTEP's AppKit to support
 * "promised" files (declare a drag now, supply the actual bytes lazily once Workspace asks where to
 * put them), which is a Mac OS X 10.2+ addition (NSFilesPromisePboardType,
 * -namesOfPromisedFilesDroppedAtDestination:) not present in OPENSTEP 4.2's AppKit. */
- (void)droppedFiles:(NSArray *)paths
{
    if (!ready || dead || ![paths count]) return;
    [self queueUploadsOfPaths:paths];
}

- (void)newFolder:(id)sender
{
    NSString *n = [PromptPanel askText:@"Name of the new folder:" title:@"New Folder"];
    n = n ? ui_trim(n) : nil;
    if (n && [n length]) [self queueMkdir:[self remoteJoin:n]];
}

- (void)rename:(id)sender
{
    NSArray *sel = [self selectedEntries];
    SFTPEntry *e;
    NSString *n;
    if ([sel count] != 1) { NSRunAlertPanel(@"Rename", @"Select exactly one item.", @"OK", nil, nil); return; }
    e = [sel objectAtIndex:0];
    n = [PromptPanel askText:[NSString stringWithFormat:@"New name for %@:", e->name] title:@"Rename" initial:e->name];
    n = n ? ui_trim(n) : nil;
    if (n && [n length] && ![n isEqual:e->name]) [self queueRename:[self remoteJoin:e->name] to:[self remoteJoin:n]];
}

- (void)delete:(id)sender
{
    NSArray *sel = [self selectedEntries];
    NSString *msg;
    int i;
    if ([sel count] == 0) { NSRunAlertPanel(@"Delete", @"Select something to delete.", @"OK", nil, nil); return; }
    msg = [sel count] == 1
        ? [NSString stringWithFormat:@"Delete %@? This cannot be undone.", ((SFTPEntry *)[sel objectAtIndex:0])->name]
        : [NSString stringWithFormat:@"Delete these %d items? This cannot be undone.", (int)[sel count]];
    if (NSRunAlertPanel(@"Delete from the server?", @"%@", @"Delete", @"Cancel", nil, msg) != NSAlertDefaultReturn)
        return;
    for (i = 0; i < (int)[sel count]; i++) {
        SFTPEntry *e = [sel objectAtIndex:i];
        [self queueRemove:[self remoteJoin:e->name] directory:e->isDir];
    }
}

/* ---------------------------------------------------------------- */
/* window delegate                                                  */

- (BOOL)windowShouldClose:(id)sender
{
    if (busy && !dead && NSRunAlertPanel(@"Transfer in progress", @"Closing the file browser will cancel the transfer.",
                                         @"Close", @"Keep Open", nil) != NSAlertDefaultReturn)
        return NO;
    return YES;
}

- (void)windowWillClose:(NSNotification *)notification
{
    [jobs removeAllObjects];
    if (xfer) sftp_xfer_cancel((sftp_xfer *)xfer);
    [window setDelegate:nil];
    [session browserClosed:self];
}

@end
