#include <windows.h>
#include <stdio.h>
#include <getopt.h>
#include <Tlhelp32.h>
#include <psapi.h>
#include <winnt.h>


static char *output_format;
static char *process_name;
static char *file_path;
static int priority_process_name=0;
static int priority_current_process=0; 
static int mockingjay_flag=0;


void parseSectionHeader(){
  FILE *pEfile=fopen(file_path,"r");
  IMAGE_DOS_HEADER dos_header;
  IMAGE_NT_HEADERS nt_headers;
  fseek(pEfile,0,SEEK_SET);
  fread(&dos_header,sizeof(IMAGE_DOS_HEADER),1,pEfile);
  fseek(pEfile,dos_header.e_lfanew,SEEK_SET);
  fread(&nt_headers,sizeof(IMAGE_NT_HEADERS),1,pEfile);
  IMAGE_SECTION_HEADER section_header[nt_headers.FileHeader.NumberOfSections];
	for (int i = 0; i <  nt_headers.FileHeader.NumberOfSections; i++) {
		int offset = (dos_header.e_lfanew + sizeof(DWORD)+ sizeof(IMAGE_FILE_HEADER)+nt_headers.FileHeader.SizeOfOptionalHeader )+ (i * sizeof(IMAGE_SECTION_HEADER)) ;
    fseek(pEfile, offset, SEEK_SET);
		fread(&section_header[i], sizeof(IMAGE_SECTION_HEADER), 1, pEfile);
	
  }
  for (int i = 0; i < nt_headers.FileHeader.NumberOfSections; i++) {
      if((section_header[i].Characteristics & IMAGE_SCN_MEM_READ) &&(section_header[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)){
       printf("[+] Found The Section having rwx permission\n");
       printf("=================================================================\n");
       printf("=================================================================\n");
       printf("[+] Name:%.8s\n",section_header[i].Name);
       printf("[+] VirtualAddress: 0x%X\n",section_header[i].VirtualAddress);
       printf("[+] VirtualSize: 0x%X\n", section_header[i].Misc.VirtualSize);
       printf("[+] PointerToRawData: 0x%X\n", section_header[i].PointerToRawData);
       printf("[+] SizeofRawData: 0x%X\n",section_header[i].SizeOfRawData);
       printf("[+] Characteristics: 0x%X\n\n",section_header[i].Characteristics);
      }  
}

}

BOOL fileinfo(){
  FILE *pEfile=fopen(file_path,"r");
  IMAGE_DOS_HEADER dos_header;
  WORD pefile_type;
  fseek(pEfile,0,SEEK_SET);
  fread(&dos_header,sizeof(IMAGE_DOS_HEADER),1,pEfile);

  fseek(pEfile,dos_header.e_lfanew+sizeof(DWORD)+ sizeof(IMAGE_FILE_HEADER), SEEK_SET);
  fread(&pefile_type,sizeof(WORD), 1, pEfile);
  
	if (pefile_type == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("[+] EXE is 32 bit\n");
    return 1;
	}
	else {
    if(pefile_type==IMAGE_NT_OPTIONAL_HDR64_MAGIC){
      printf("[+] EXE is 64 bit\n");
      return 1;
    }
    else  {
      printf("[+] Can not determined the File Type\n");
      return 0;
    }
	

}
}
BOOL isPeFile(){
  FILE *pEfile=fopen(file_path,"r");
  IMAGE_DOS_HEADER dos_header;
  fseek(pEfile,0,SEEK_SET);
  fread(&dos_header,sizeof(IMAGE_DOS_HEADER),1,pEfile);
  if(dos_header.e_magic == IMAGE_DOS_SIGNATURE){
    printf("[+] PE File Found %s \n",file_path);
    return 1;
  }
  else{
    printf("[+] Not a PE File\n");
    return 0;
  }
   
}

BOOL IsFile(){
  FILE *pEfile=fopen(file_path,"r");
  if(pEfile==NULL){
    printf("[+] File Not Found\n");
    fclose(pEfile);
    return 0;
  }
  else{
    fclose(pEfile);
    return 1;
  }
}

void ErrorMessagess(DWORD status){
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,NULL,status,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),buffer,sizeof(buffer)/sizeof(char),NULL);
    printf("[+] Error is %s \n", buffer);
}

void MockingJay_Parser(){
  BOOL value=IsFile();
  if(value){
    printf("[+] File Found : %s\n",file_path);
    if(isPeFile() && fileinfo()){
       parseSectionHeader();
    }
  }
}


void Dllparser(HANDLE prcsID){
  DWORD cb=1000;
  HMODULE lphmoduleArray[cb];
  HMODULE *lphmodule=lphmoduleArray;
  DWORD lpcbNeeded;
  unsigned char buffer[500];
  unsigned char buffer_psecuritydescriptor[500];
  PSECURITY_DESCRIPTOR  pSecurityDescriptor=buffer_psecuritydescriptor;
  HMODULE module_name;
  LPSTR lpbasename=buffer;
  DWORD lpnLengthNeeded;
  if((EnumProcessModulesEx(prcsID,lphmodule,cb,(LPDWORD)&lpcbNeeded,LIST_MODULES_ALL))!=0){
     cb=lpcbNeeded/sizeof(HMODULE);
 
  }
  if((EnumProcessModulesEx(prcsID,lphmodule,cb,(LPDWORD)&lpcbNeeded,LIST_MODULES_ALL))!=0){
    printf("[+] Enumerating Modules...\n");
    printf("=================================================================================\n");
    printf("=================================================================================\n");
  }
  
  for(int handlesw=1;handlesw<cb;handlesw++){

    module_name=lphmoduleArray[handlesw];

    if(GetModuleFileNameExA(prcsID,module_name,lpbasename,500)!=0){
      if((strstr(lpbasename,process_name)) == NULL){      
          printf("[+] Module Found %s\n",lpbasename);

     
    }
    }
  }
  
}

DWORD FindTargetProc( const char *targetprocess){
    HANDLE prcs;
    int flag;
    PROCESSENTRY32 pe32;
    DWORD pid=0;
    prcs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(prcs==INVALID_HANDLE_VALUE){
        printf("[+] Error Occured while Taking Snapshot of the process");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);
    }
    else{
          pe32.dwSize=sizeof(PROCESSENTRY32);
          //retrieving info about the first process
          BOOL values=Process32First(prcs,(LPPROCESSENTRY32)&pe32);
          if(values==FALSE){
             printf("Error Occured while Copying the First Process to buffer");
            DWORD dwStatusError=GetLastError();
            ErrorMessagess(dwStatusError);
            exit(0);
          }
          
          else{
             while(Process32Next(prcs,(LPPROCESSENTRY32)&pe32)){
                int cmp=strcasecmp(targetprocess,pe32.szExeFile);
                if(cmp==0){
                    printf("[+] Process found\n");
                    pid=pe32.th32ProcessID;
                    flag=1;
                    break;
                }
                
             }
             if(flag !=1){
                printf("[+] Could not find the process\n");
                exit(0);
             }
          }

    }
    return pid;
}

/* void parse_output_format(){
  printf("[+] Output format is %s",output_format);

}
*/
void process_parsing(){
  DWORD PID=FindTargetProc(process_name);
    HANDLE prcsID;
    prcsID=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,PID);
    if(prcsID==NULL){
        printf("[+] Error: Can not create handle to process");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);
    }
    else{
      printf("[+] Handle to Process Obtained\n");
    }
    //using handle to find different modules 
    Dllparser(prcsID);
    if(mockingjay_flag){
       MockingJay_Parser();
    }
}
void set_priority(){
  if(priority_process_name){
        process_parsing();
    }
  else {
        printf("[+] Process Name Not provided\n");
        exit(0);
    }
  
}

int main (int argc, char **argv)
{

  int c;

  while (1)
    {
      static struct option long_options[] =
        {
          {"process_name",  required_argument, 0, 'p'},
          {"mockinjay_path",required_argument,0,'m'},
          {0, 0, 0, 0}
        };
      int option_index = 0;

      c = getopt_long (argc, argv, "m:p:",
                       long_options, &option_index);

      if (c == -1) {
        set_priority(); 
        break;
      }
      switch (c)
        {
        case 0:
          if (long_options[option_index].flag != 0)
            break;
          printf ("option %s", long_options[option_index].name);
          if (optarg)
            printf (" with arg %s", optarg);
          printf ("\n");
          break;

        case 'p':
          priority_process_name=1;
          process_name=optarg;
          break;
        case 'm':
          mockingjay_flag=1;
          file_path=optarg;

        case '?':
          /* getopt_long already printed an error message. */
          break;

        default:
          printf("default option");
        }
    }

  /* Print any remaining command line arguments (not options). */
  if (optind < argc)
    {
      printf ("non-option ARGV-elements: ");
      while (optind < argc)
        printf ("%s ", argv[optind++]);
      putchar ('\n');
    }

  exit (0);
}

