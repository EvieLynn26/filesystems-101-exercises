#include <solution.h>

#include <ctype.h> 
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>

const size_t BUFF_SIZE = 1000;

int check_pid(char* name) {
	char* name_tmp_ptr = name;
	while (*name_tmp_ptr != '\0') {
		if (isdigit(*name_tmp_ptr) == 0) {
			return 0;
		}
		++name_tmp_ptr;
	}
	return 1;
}


void ps(void)
{
	DIR *dir;
    struct dirent *entry;

    dir = opendir("/proc");
    if (dir == NULL) {
        exit(1);
    };

    while ((entry = readdir(dir)) != NULL) {
		pid_t pid = 0;
		if (check_pid(entry->d_name) == 1) { // if pid

			sscanf(entry->d_name, "%d", &pid);
			//printf("PID = %d\n", pid);

			//----process exe--------------
			char tmp_path_exe[BUFF_SIZE];
			sprintf(tmp_path_exe, "/proc/%s/exe", entry->d_name);
			
			char exe[BUFF_SIZE];
			int nbytes = readlink(tmp_path_exe, exe, 8192); 
			if (nbytes == -1) {
				report_error(tmp_path_exe, errno);
				continue;	
			}
			exe[nbytes] = '\0';
			//-----------------------------

			//----process argv-------------
			char tmp_path_cmdline[BUFF_SIZE];
			sprintf(tmp_path_cmdline, "/proc/%s/cmdline", entry->d_name);
			FILE* file = fopen(tmp_path_cmdline, "r");
			if (file == NULL) {
				report_error(tmp_path_cmdline, errno);
				continue;	
			}

			char *argv_buf[BUFF_SIZE];
    		size_t argv_sizes[BUFF_SIZE];
    		for (size_t j = 0; j < BUFF_SIZE; ++j) {
				argv_buf[j] = (char*) malloc(BUFF_SIZE * sizeof(char));
				argv_sizes[j] = BUFF_SIZE * sizeof(char);
    		}
    		char *argv[BUFF_SIZE];
			int tmp_i = 0;
        	while (getdelim(&argv_buf[tmp_i], &argv_sizes[tmp_i], '\0', file) != -1 && argv_buf[tmp_i][0] != 0) {
            	argv[tmp_i] = argv_buf[tmp_i];
            	++tmp_i;
        	}
        	argv[tmp_i] = NULL;
        	fclose(file);
			//-----------------------------------------

			//----process envp-------------
			char tmp_path_environ[BUFF_SIZE];
			sprintf(tmp_path_environ, "/proc/%s/environ", entry->d_name);
			file = fopen(tmp_path_environ, "r");
			if (file == NULL) {
				report_error(tmp_path_environ, errno);
				continue;	
			}

    		char *envp_buf[BUFF_SIZE];
    		size_t envp_sizes[BUFF_SIZE];
    		for (size_t j = 0; j < BUFF_SIZE; ++j) {
				envp_buf[j] = (char*) malloc(BUFF_SIZE * sizeof(char));
				envp_sizes[j] = BUFF_SIZE * sizeof(char);
    		}
    		char *envp[BUFF_SIZE];

			tmp_i = 0;
        	while (getdelim(&envp_buf[tmp_i], &envp_sizes[tmp_i], '\0', file) != -1 && envp_buf[tmp_i][0] != 0) {
            	envp[tmp_i] = envp_buf[tmp_i];
            	++tmp_i;
        	}
        	envp[tmp_i] = NULL;
        	fclose(file);
			//-----------------------------------------

			report_process(pid, exe, argv, envp);

			for (size_t j = 0; j < BUFF_SIZE; ++j) {
        		free(argv_buf[j]);
        		free(envp_buf[j]);
    		}
		} // if pid
	}

    closedir(dir);

}
