//
//  main.m
//  watcher
//
//  Created by Anthony Viriya on 23/05/2022.
//exi

#import <Foundation/Foundation.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include "esf_notify_handler.h"
#include "esf_auth_handler.h"
#include <pthread.h>
#include <spawn.h>


static bool handle_event(es_client_t *c, const es_message_t *msg, NSMutableArray* pids_to_monitor){
    const pid_t parent_pid = audit_token_to_pid(msg->process->audit_token);
    const char* parent_process = msg->process->executable->path.data;
    bool return_value = true;
    NSLock *arrayLock = [[NSLock alloc] init];
    [arrayLock lock];
    if([pids_to_monitor containsObject:[NSNumber numberWithInt:parent_pid]]){
        [arrayLock unlock];
        switch (msg->event_type) {
            case ES_EVENT_TYPE_NOTIFY_FORK:{
                [arrayLock lock];
                handle_notify_fork(msg, &pids_to_monitor, parent_pid, parent_process);
                [arrayLock unlock];
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_EXIT:{
                [arrayLock lock];
                handle_notify_exit(msg, &pids_to_monitor, parent_pid, parent_process);
                [arrayLock unlock];
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_EXEC:{
                [arrayLock lock];
                handle_notify_exec(msg, &pids_to_monitor, parent_pid, parent_process);
                [arrayLock unlock];
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_RENAME:{
                handle_notify_rename(parent_pid, parent_process, msg);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_COPYFILE:{
                handle_notify_copyfile(parent_pid, parent_process, msg);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_CLONE:{
                handle_notify_clone(parent_pid, parent_process, msg);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_CREATE:{
                handle_notify_create(parent_pid, parent_process, msg);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_WRITE:{
                handle_notify_write(parent_pid, parent_process, msg);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_OPEN:{
                handle_notify_open(parent_pid, parent_process, msg);
                break;
            }
        }
    }
    
    return return_value;
}

pid_t run_binary(const char* cmd, char** argv) {
    pid_t pid;
    posix_spawnattr_t spawn_attrs;
    posix_spawnattr_init(&spawn_attrs);
    posix_spawnattr_setflags(&spawn_attrs, POSIX_SPAWN_START_SUSPENDED);
    int status;
    status = posix_spawn(&pid, cmd, NULL, &spawn_attrs, argv, NULL);
    if(status != 0) {
        fprintf(stderr, "[-] Error on posix_spawn: %s\n", strerror(status));
        pid = -1;
    }
    posix_spawnattr_destroy(&spawn_attrs);
    return pid;
}

int main(int argc, const char * argv[]) {
    int pid;
    bool have_suspended_process = false;
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s [-pbh] [ARG...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if (strcmp(argv[1], "-p") == 0 ) {
        pid = atoi(argv[2]);
    } else if (strcmp(argv[1], "-b") == 0) {
        int new_argc = argc-3;
        char** new_argv = (char**) malloc(new_argc+1 * sizeof(const char *));
        int i;
        new_argv[0] = strrchr(argv[2], '/');
        for(i=3;i<argc;++i) {
            new_argv[i-2] = (char *) argv[i];
        }
        pid = run_binary(argv[2], new_argv);
        if (pid == -1) {
            exit(EXIT_FAILURE);
        }
        have_suspended_process = true;
    } else if (strcmp(argv[1], "-h") == 0) {
        printf("Arguments:\n");
        printf("-p PID: monitor process with specific PID\n");
        printf("-b \"/Path/To/Wanted Binary.app/Contents/MacOS/Wanted Binary\" \"arguments for binary\": Launch Wanted Binary in a suspended state, monitor the PID, and continue execution\n");
        printf("-h: help, to show this banner\n");
        exit(EXIT_SUCCESS);
    }else {
        fprintf(stderr, "Usage: sudo %s [-pbh] [ARG...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    es_client_t *client;
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_COPYFILE,
        ES_EVENT_TYPE_NOTIFY_CLONE,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_OPEN
    };
    NSMutableArray* pids_to_monitor;
    pids_to_monitor = [[NSMutableArray alloc] initWithCapacity:1];
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        handle_event(c, msg, pids_to_monitor);
    });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        printf("[-] Failed to create a new es client: %d\n", result);
        switch (result) {
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                printf("[-] Extension is missing entitlement.\n");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
                printf("[-] Extension is not running as root.\n");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
                printf("[-] Invalid argument to es_new_client(); client or handler was null.\n");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
                printf("[-] Exceeded maximum number of simultaneously-connected ES clients.\n");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
                printf("[-] Failed to connect to the Endpoint Security subsystem.\n");
                break;
            case ES_NEW_CLIENT_RESULT_SUCCESS:
                break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                printf("[-] Not permitted.\n");
                break;
        }

        return -1;
    }
    printf("Attempting to monitor PID %d\n", pid);
    BOOL is_running = YES;
    [pids_to_monitor addObject:[NSNumber numberWithInt:pid]];
    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        printf("[-] Failed to subscribe to events\n");
        es_delete_client(client);
        exit(EXIT_FAILURE);
    }else{
        printf("[+] Process %d is being monitored\n", pid);
    }
    if (have_suspended_process) {
        kill(pid, SIGCONT);
    }
    char input[255];
    while (is_running){
        printf("Type `exit` to exit.\n");
        scanf("%s", input);
        if(strcmp(input, "exit") == 0){
            is_running = NO;
        }
    }
    es_delete_client(client);
    return 0;
}
