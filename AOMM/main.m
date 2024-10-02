// source: https://github.com/objective-see/TAOMM/blob/main/Code/Vol%20II/CH%201/enumerateProcesses/enumerateProcesses/main.m
//  main.m
//  AOMM
//
//  Created by Alexander on 10/1/24.
//
//TODO: fix getArgs, pg. 13

#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <libproc.h>
#import <AppKit/AppKit.h>

// Function declarations
NSData* getAuditToken(pid_t pid);
NSMutableArray* getAllProcessID(void);
int getPath(pid_t pid);
NSString* getAppName(pid_t pid);

int main(int argc, const char *argv[]) {
    NSMutableArray* pids = nil;
    pids = getAllProcessID();
    
    return 0;
}

//List all running processes
NSMutableArray* getAllProcessID(void) {
    int32_t processesCount = 0;
    
    //Dynamically retrieve max # of running processes
    size_t length = sizeof(processesCount);
    sysctlbyname("kern.maxproc", &processesCount, &length, NULL, 0);
    
    //Generate list of process IDs by allocating buffer with size: proc * procSize
    pid_t* pids = calloc((unsigned long)processesCount, sizeof(pid_t));
    processesCount = proc_listallpids(pids, processesCount * sizeof(pid_t));
    
    printf("Found %d running processes\n", processesCount);
    
    NSMutableArray* allProccessID = [[NSMutableArray alloc] init]; //have to make pointer array to store pid objects
    for(int i = 0; i < processesCount; i++){
        //integer objects being added to processID object array
        [allProccessID addObject:[NSNumber numberWithInt:pids[i]]]; //fill array with pids
        printf("%d\t\n", pids[i]);
       // printf("%c", (char)getAppName(pids[i])) ### should get app name but returns numbers
    }
    
    free(pids); //free memory
    return allProccessID;
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

// get cmdl args and save them in 'arguments' ivar
NSMutableArray* getArgs(pid_t pid) {
    int mib[3] = {0}; // initialize Management Information Base array
    int systemMaxArgs = 0;
    int numArgs = 0;
    NSString* argument = nil;
    char* parser = NULL;
    size_t size = sizeof(systemMaxArgs);
    
    mib[0] = CTL_KERN;
    mib[1] = KERN_ARGMAX; //max size of arguments
    sysctl(mib, 2, &systemMaxArgs, &size, NULL, 0);
    
    char* args = malloc(systemMaxArgs); // Create buffer for arguments
    
    size = (size_t)systemMaxArgs;
        
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROCARGS2; //KERN_PROCARGS2 == Num args (int argc), Process path, argv[0]/[1]/[...]
    mib[2] = pid;
    sysctl(mib, 3, args, &size, NULL, 0);
    
    NSMutableArray* extractedArgs = [NSMutableArray array];
    memcpy(&numArgs, args, sizeof(numArgs));
    parser = argument + sizeof(numArgs);
    
    while (NULL != *++parser);
    while (NULL == *++parser);
    while (extractedArgs.count < numArgs) {
        [extractedArgs addObject:[NSString stringWithUTF8String:parser]];
        parser += strlen(parser) + 1;
    }
    
    return 0;
}
