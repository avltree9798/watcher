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


static bool handle_event(es_client_t *c, const es_message_t *msg, NSMutableArray* pids_to_monitor){
    const pid_t parent_pid = audit_token_to_pid(msg->process->audit_token);
    const char* parent_process = msg->process->executable->path.data;
    bool return_value = true;
    if([pids_to_monitor containsObject:[NSNumber numberWithInt:parent_pid]]){
        switch (msg->event_type) {
            case ES_EVENT_TYPE_NOTIFY_FORK:{
                handle_notify_fork(msg, &pids_to_monitor, parent_pid, parent_process);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_EXIT:{
                handle_notify_exit(msg, &pids_to_monitor, parent_pid, parent_process);
                break;
            }
            case ES_EVENT_TYPE_NOTIFY_EXEC:{
                handle_notify_exec(msg, &pids_to_monitor, parent_pid, parent_process);
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

int main(int argc, const char * argv[]) {
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
    
    int pid;
    printf("Enter the PID you want to monitor: ");
    scanf("%d", &pid);
    fflush(stdin);
    
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
    }else{
        printf("[+] Process %d is being monitored\n", pid);
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
