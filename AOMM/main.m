//
//  main.m
//  AOMM
//
//  Created by Alexander on 10/1/24.
//
//TODO: print out the audit token, pg. 6 Paths and Names

#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <libproc.h>
#import <AppKit/AppKit.h>

// Function declarations
NSData* getAuditToken(pid_t pid);
NSMutableArray* getProcessIDs(void);
int getPath(pid_t pid);
NSString* getAppName(pid_t pid);

int main(int argc, const char *argv[]) {
    NSMutableArray* pids = nil;
    pids = getProcessIDs();
    
    return 0;
}

//List all running processes
NSMutableArray* getProcessIDs(void) {
    int32_t processesCount = 0;
    
    //Dynamically retrieve max # of running processes
    size_t length = sizeof(processesCount);
    sysctlbyname("kern.maxproc", &processesCount, &length, NULL, 0);
    
    //Generate list of process IDs by allocating buffer with size: proc * procSize
    pid_t* pids = calloc((unsigned long)processesCount, sizeof(pid_t));
    processesCount = proc_listallpids(pids, processesCount * sizeof(pid_t));
    
    printf("Found %d running processes\n", processesCount);
    
    NSMutableArray* processIDs = [[NSMutableArray alloc] init]; //have to make pointer array to store pid objects
    for(int i = 0; i < processesCount; i++){
        //integer objects being added to processID object array
        [processIDs addObject:[NSNumber numberWithInt:pids[i]]]; //fill array with pids
        printf("%d\t\n", pids[i]);
       // printf("%c", (char)getAppName(pids[i])) ### should get app name but returns numbers
    }
    
    free(pids); //free memory
    return processIDs;
}

//Obtain audit token for a process
NSData* getAuditToken(pid_t pid) {
    NSData* auditToken = nil;
    task_name_t task = {0}; // initialize auditToken, tasks and tokens
    audit_token_t token = {0};
    mach_msg_type_number_t info_size = TASK_AUDIT_TOKEN_COUNT;
    
    task_name_for_pid(mach_task_self(), pid, &task); //required to hold audit token
    task_info(task, TASK_AUDIT_TOKEN, (integer_t *) &token, &info_size); //populate task with audit token
    auditToken = [NSData dataWithBytes:&token length:sizeof(audit_token_t)]; //make token an object
    
    return auditToken;
}

//find the file path for a process
int getPath(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    return proc_pidpath(pid, path, PROC_PIDPATHINFO_MAXSIZE);
}

//Extract application name from running process
NSString* getAppName(pid_t pid) {
    NSString* name = nil;
    NSRunningApplication* app = [NSRunningApplication runningApplicationWithProcessIdentifier:pid];
    if (nil != app) {
        NSBundle* bundle = [NSBundle bundleWithURL:app.bundleURL];
        name = bundle.infoDictionary[@"CFBundleName"];
    }
    return name;
}
