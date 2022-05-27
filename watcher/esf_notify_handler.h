//
//  esf_notify_handler.h
//  watcher
//
//  Created by Anthony Viriya on 27/05/2022.
//
#import <Foundation/Foundation.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

#ifndef esf_notify_handler_h
#define esf_notify_handler_h
void handle_notify_exec(const es_message_t *msg, NSMutableArray** pids_to_monitor, const pid_t parent_pid, const char* parent_process);
void handle_notify_exit(const es_message_t *msg, NSMutableArray** pids_to_monitor, const pid_t parent_pid, const char* parent_process);
void handle_notify_fork(const es_message_t *msg, NSMutableArray** pids_to_monitor, const pid_t parent_pid, const char* parent_process);
void handle_notify_rename(const pid_t parent_pid, const char* parent_process, const es_message_t *msg);
void handle_notify_copyfile(const pid_t parent_pid, const char* parent_process, const es_message_t *msg);
void handle_notify_clone(const pid_t parent_pid, const char* parent_process, const es_message_t *msg);
void handle_notify_create(const pid_t parent_pid, const char* parent_process, const es_message_t *msg);
void handle_notify_write(const pid_t parent_pid, const char* parent_process, const es_message_t *msg);
void handle_notify_open(const pid_t parent_pid, const char* parent_process, const es_message_t *msg);
#endif /* esf_notify_handler_h */
