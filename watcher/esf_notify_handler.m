//
//  esf_notify_handler.m
//  watcher
//
//  Created by Anthony Viriya on 27/05/2022.
//

#import <Foundation/Foundation.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>


void handle_notify_exec(const es_message_t *msg, NSMutableArray** pids_to_monitor, const pid_t parent_pid, const char* parent_process){
    pid_t new_process_pid = audit_token_to_pid(msg->event.exec.target->audit_token);
    printf("[NOTIFY] [EXEC] [%d] %s -> [%d] %s", parent_pid, parent_process, new_process_pid, msg->event.exec.target->executable->path.data);
    [*pids_to_monitor addObject:[NSNumber numberWithInt:new_process_pid]];
}


void handle_notify_exit(const es_message_t *msg, NSMutableArray** pids_to_monitor, const pid_t parent_pid, const char* parent_process){
    printf("[NOTIFY] [EXIT] [%d] %s\n", parent_pid, parent_process);
    [*pids_to_monitor removeObject:[NSNumber numberWithInt:parent_pid]];
}

void handle_notify_fork(const es_message_t *msg, NSMutableArray** pids_to_monitor, const pid_t parent_pid, const char* parent_process){
    pid_t child_pid = audit_token_to_pid(msg->event.fork.child->audit_token);
    printf("[NOTIFY] [FORK] [%d] %s -> [%d] %s\n", parent_pid, parent_process, child_pid, msg->event.fork.child->executable->path.data);
    [*pids_to_monitor addObject:[NSNumber numberWithInt:child_pid]];
}

void handle_notify_rename(const pid_t parent_pid, const char* parent_process, const es_message_t *msg) {
    const char* destination_file = NULL;
    const char* destination_dir = ".";
    const char* source = msg->event.rename.source->path.data;
    if(msg->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH){
        destination_file = msg->event.rename.destination.new_path.filename.data;
        destination_dir = msg->event.rename.destination.new_path.dir->path.data;
    }else{
        destination_file = msg->event.rename.destination.existing_file->path.data;
    }
    
    printf("[NOTIFY] [RENAME] [%d] %s: %s -> %s/%s\n", parent_pid, parent_process, source, destination_dir, destination_file);
}

void handle_notify_copyfile(const pid_t parent_pid, const char* parent_process, const es_message_t *msg) {
    const char* source = msg->event.copyfile.source->path.data;
    const char* destination_dir = msg->event.copyfile.target_dir->path.data;
    const char* destination_file = msg->event.copyfile.target_file->path.data;
    printf("[NOTIFY] [COPYFILE] [%d] %s: %s -> %s/%s\n", parent_pid, parent_process, source, destination_dir, destination_file);
}

void handle_notify_clone(const pid_t parent_pid, const char* parent_process, const es_message_t *msg) {
    const char* source = msg->event.clone.source->path.data;
    const char* destination_dir = msg->event.clone.target_dir->path.data;
    const char* destination_file = msg->event.clone.target_name.data;
    printf("[NOTIFY] [CLONE] [%d] %s: %s -> %s/%s\n", parent_pid, parent_process, source, destination_dir, destination_file);
}

void handle_notify_create(const pid_t parent_pid, const char* parent_process, const es_message_t *msg) {
    const char* destination_file = NULL;
    const char* destination_dir = ".";
    if(msg->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH){
        destination_file = msg->event.create.destination.new_path.filename.data;
        destination_dir = msg->event.create.destination.new_path.dir->path.data;
    }else{
        destination_file = msg->event.create.destination.existing_file->path.data;
    }
    printf("[NOTIFY] [CREATE] [%d] %s: %s/%s\n", parent_pid, parent_process, destination_dir, destination_file);
}

void handle_notify_write(const pid_t parent_pid, const char* parent_process, const es_message_t *msg) {
    const char* target = msg->event.write.target->path.data;
    printf("[NOTIFY] [WRITE] [%d] %s: %s\n", parent_pid, parent_process, target);
}

void handle_notify_open(const pid_t parent_pid, const char* parent_process, const es_message_t *msg) {
    const char* target = msg->event.open.file->path.data;
    printf("[NOTIFY] [OPEN] [%d] %s: %s\n", parent_pid, parent_process, target);
}
