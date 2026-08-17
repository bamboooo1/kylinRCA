#include <bpf/libbpf.h>
#include <iostream>
#include <cstring>
#include <cerrno>

int main(){
    const char *bpf_object_path = "build/core_smoke.bpf.o";

    struct bpf_object *obj = bpf_object__open_file(bpf_object_path,nullptr);
    //打开.o文件，打开后的BPF文件内容由指针obj指向。
    if(obj == nullptr){
        std::cerr << "Failed to open BPF object:"
                  << std::strerror(errno)
                  << std::endl;
        return 1;
    }
    std::cout << "Successfully opened BPF object:"
              << bpf_object_path
              << std::endl;
    
    struct bpf_program *prog = nullptr;
    while((prog = bpf_object__next_program(obj, prog)) != nullptr){
        std::cout << "BPF program name: "
                  << bpf_program__name(prog) 
                  << std::endl;

        std::cout << "BPF section: "
                  << bpf_program__section_name(prog)
                  << std::endl;
    }// 打印bpf对象里的program和所属的section信息， program是对应的源程序，section是这个程序挂载在内核哪一个操作上。

    int err = bpf_object__load(obj);
    if(err != 0){
        std::cout << "Failed to load BPF object, error: "
                  << err
                  << std::endl;
        bpf_object__close(obj);
        return 1;
    }
    std::cout << "Successfully loaded BPF object into kernel"
              << std::endl; //将BPF程序交给linux内核；

    struct bpf_program *target_prog = bpf_object__find_program_by_name(obj, "core_smoke");
    if(target_prog == nullptr){
        std::cerr << "Failed to find BPF program: core_smoke"
                  << std::endl;
        bpf_object__close(obj);
        return 1;
    }// 在这个object中重新找到目标程序
    struct bpf_link *link = bpf_program__attach(target_prog);
    if(link == nullptr){
        std::cerr << "Failed to attach BPF program: "
                  << std::strerror(errno)
                  << std::endl;
        bpf_object__close(obj);
        return 1;
    }
    std::cout << "Succesfully attached BPF program"
              << std::endl; // 建立BPF程序（core_smoke.bpf.c)与tracepoint(tracepoint/syscalls/sys_enter_getpid)的链接
    std::cout << "Press Enter to stop..." <<  std::endl;
    std::cin.get();
    bpf_link__destroy(link);// 按下enter后拆掉链接；
    std::cout << "The link is destroyed" <<  std::endl;


    bpf_object__close(obj);//使用完obj指向的对象后，把libbpf为它占用的资源释放
    return 0;
}