#ifndef _SAMPLE_KEYS_H
# define _SAMPLE_KEYS_H

/*
 * Keys used in the JSON/xml versions of
 * sample's output.
 */

# define TOP_KEY	"sample-information"
# define PROCESS_LIST	"processes"
# define PROCESS_KEY	"process"
# define KMOD_LIST	"kmod-list"
# define KMOD_ENTRY	"kmod-entry"
# define THREAD_LIST	"threads"
# define THREAD_KEY	"thread"
# define STACKS_LIST	"stacks"
# define FILE_LIST	"mapped-file"

# define VERSION_KEY	"version"
# define ARCH_KEY	"architecture"

# define KMODULE_ID	"module_id"
# define KMODULE_ADDR	"module_address"
# define KMODULE_SIZE	"module_size"
# define KMODULE_PATH	"module_path"

# define PROC_PID_KEY	"process_id"
# define PROC_NAME_KEY	"process_name"
# define PROC_PATH_KEY	"process_path"
# define PROC_COUNT_KEY	"sample_count"

# define THREAD_ID_KEY	"thread-id"
# define THREAD_STACKS_KEY	"stacks"

# define FILE_PATH_KEY	"path"
# define FILE_ADDR_KEY	"address"
# define FILE_END_KEY	"end"

# define SAMPLE_COUNT_KEY	"sample_count"
# define SAMPLE_ADDR_KEY	"sample_address"
# define SAMPLE_FILE_KEY	"filename"
# define SAMPLE_OFFSET_KEY	"offset"
# define SAMPLE_SYMBOL_KEY	"symbol_name"
# define SAMPLE_SYMOFF_KEY	"symbol_offset"

#endif /* _SAMPLE_KEYS_H */
