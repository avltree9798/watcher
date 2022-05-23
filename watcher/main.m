//
//  main.m
//  watcher
//
//  Created by Anthony Viriya on 23/05/2022.
//exi

#import <Foundation/Foundation.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>


NSMutableArray* pids_to_monitor;

static void handle_event(es_client_t *c, const es_message_t *msg){
    pid_t parent_pid = audit_token_to_pid(msg->process->audit_token);
    char* parent_process = msg->process->executable->path.data;
    if([pids_to_monitor containsObject:[NSNumber numberWithInt:parent_pid]]){
        switch (msg->event_type) {
            case ES_EVENT_TYPE_NOTIFY_FORK:{
                pid_t child_pid = audit_token_to_pid(msg->event.fork.child->audit_token);
                printf("[+] FORK [%d] %s -> [%d] %s\n", parent_pid, parent_process, child_pid, msg->event.fork.child->executable->path.data);
                [pids_to_monitor addObject:[NSNumber numberWithInt:child_pid]];
            }
            break;
            
            case ES_EVENT_TYPE_NOTIFY_EXIT:{
                NSNumber* pid = [NSNumber numberWithInt:parent_pid];
                if([pids_to_monitor containsObject:pid]){
                    printf("[+] EXIT [%d] %s.\n", parent_pid, parent_process);
                    [pids_to_monitor removeObject:pid];
                }
            }
            break;
            
            case ES_EVENT_TYPE_NOTIFY_EXEC:{
                    pid_t new_process_pid = audit_token_to_pid(msg->event.exec.target->audit_token);
                    printf("[+] EXEC [%d] %s -> [%d] %s", parent_pid, parent_process, new_process_pid, msg->event.exec.target->executable->path.data);
                    [pids_to_monitor addObject:[NSNumber numberWithInt:new_process_pid]];
            }
            break;
        }
    }
}

int main(int argc, const char * argv[]) {
    es_client_t *client;
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT
    };
    
    pids_to_monitor = [[NSMutableArray alloc] initWithCapacity:1];
    
    int pid;
    printf("Enter the PID you want to monitor: ");
    scanf("%d", &pid);
    fflush(stdin);
    
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        handle_event(c, msg);
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
