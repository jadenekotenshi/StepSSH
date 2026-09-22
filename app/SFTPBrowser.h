#import "Compat.h"

@class SSHSession;

/* One remote file, as shown in a row of the browser. */
@interface SFTPEntry : NSObject
{
@public
    NSString *name;
    BOOL      isDir, isLink;
    unsigned long long size;
    unsigned  mtime, perms;
}
- (NSComparisonResult)compareToEntry:(SFTPEntry *)other;   /* folders first, then by name */
@end

/* The file browser window: a listing of one remote directory plus upload, download,
 * new folder, rename and delete.  It borrows the SSH connection of its SSHSession. */
@interface SFTPBrowser : NSObject
{
    SSHSession       *session;                   /* not retained: the session owns us */
    NSString         *host, *user;
    NSWindow         *window;
    NSTableView      *table;
    NSTextField      *pathField, *statusLabel;
    NSButton         *upBtn, *refreshBtn, *downBtn, *upBtnLoad, *mkdirBtn, *renameBtn, *deleteBtn, *cancelBtn;
    NSView           *meter;
    float             fraction;
    NSMutableArray   *entries;                   /* SFTPEntry, sorted */
    NSString         *cwd;                       /* canonical remote directory currently shown */
    NSString         *wanted;                    /* directory being navigated to */
    NSMutableArray   *jobs;                      /* queued operations */
    BOOL              ready, dead, busy, dirty, listing;
    void             *xfer;                      /* sftp_xfer * */
    FILE             *xfile;
    NSString         *xlocal;                    /* partial local file to remove on failure */
    BOOL              xisDownload;
    NSString         *walkRemote, *walkLocal;     /* remote/local dir of the "walkdir"/"walkupload" job in flight */
    BOOL              walkCancelled;              /* Cancel was hit while a walk step's request was in flight:
                                                     * its reply must not queue that directory's children */
}
- (id)initWithSession:(SSHSession *)s host:(NSString *)h user:(NSString *)u;
- (void)show;
- (void)closeWindow;
- (NSWindow *)window;
- (void)setStatus:(NSString *)s;

/* driven by the session */
- (void)sftpReady;
- (void)sftpFailed:(NSString *)message;
- (void)sessionEnded;

/* actions (buttons) */
- (void)goUp:(id)sender;
- (void)refresh:(id)sender;
- (void)pathEntered:(id)sender;
- (void)download:(id)sender;
- (void)upload:(id)sender;
- (void)newFolder:(id)sender;
- (void)rename:(id)sender;
- (void)delete:(id)sender;
- (void)cancelTransfer:(id)sender;

/* the same operations without any panels, for scripted use and tests */
- (void)goTo:(NSString *)path;
- (void)queueUploadOfLocal:(NSString *)local toRemote:(NSString *)remote;
- (void)queueDownloadOfRemote:(NSString *)remote toLocal:(NSString *)local size:(unsigned long long)size;
/* Recursive: local/remote must not exist as a plain file. Walks the source tree one directory
 * at a time as each step completes, queueing a "get"/"put" per file and a nested walk per
 * subdirectory just ahead of whatever else is queued, so one folder finishes before its sibling. */
- (void)queueWalkDownloadOfRemote:(NSString *)remote toLocal:(NSString *)local;
- (void)queueWalkUploadOfLocal:(NSString *)local toRemote:(NSString *)remote;
- (void)queueMkdir:(NSString *)remote;
- (void)queueRemove:(NSString *)remote directory:(BOOL)isDir;
- (void)queueRename:(NSString *)from to:(NSString *)to;
- (BOOL)isBusy;
- (BOOL)isReady;
- (int)entryCount;
- (SFTPEntry *)entryAtIndex:(int)i;
- (NSString *)currentPath;
- (NSString *)statusText;
@end
