# 开发日志

记录开发过程

## 2023.6.9

1. 修该页帧分配器的测试，通过`trait`可以让`Bitmap`与`Budyy`使用同一套测试方法 。
2. 替换内核中的页帧分配器为`Buddy`，并修改相应的数据结构，由于slab会提供8MB大小的块分配，这会需要2048个页因此调高了页帧分配器的最大页数。

## 2023.6.10

1. 修复`rvfs`中关于mount的实现错误，现在一个文件系统可以挂载在多个目录上
2. 修复`dbfs`中关于`readdir`的实现以及mount相关的错误，修复了`fat32`中关于`readdir`的实现错误以及mount相关错误

## 2023.6.11

1. 实现`devfs`，加入`rvfs`框架中。
2. 在内核中添加设备文件系统支持，将`ramfs`重新挂载在`/tmp`目录上

## 2023.6.12

1. 添加多核启动的支持

内核中一些数据结构需要根据CPU数量进行初始化，但是直接在内核中指定CPU数量会导致改变qemu启动的CPU参数时也随之更改内核的参数，因此我们采取了在`build.rs`中根据命令行参数生成内核参数的方法，动态地修改正确的CPU数量。

同时在实验中我们发现，`opensbi`在进入到内核时，`sstatus`的`spp`字段居然是用户态，不知道是不是qemu版本的原因，目前的解决方案就是在主函数第一句手动修改回来。

```rust
pub fn main(hart_id: usize, device_tree_addr: usize) -> ! {
    unsafe {
        set_spp(SPP::Supervisor);
    }
}
```

## 2023.6.13

1. 学习`arceos`中页表实现，将之前的实现替换掉

## 2023.6.14

1. 为`clone`系统调用添加copy-on-write功能

page-table中存在父子进程共享同一个页面的情况，这时候如果父进程释放了这个页面，那么子进程的页面也会被释放，这时候子进程的页面就会被覆盖，这是不允许的，为了解决这个问题，我们需要管理物理内存的分配情况，在前面我们已经使用伙伴系统接管了物理内存的页分配，但是出现了一些物理页被重复使用的情况，因此需要一个管理机构来记录每个物理页的使用情况。

在进程进行`fork`时，子进程获得了父进程的页表的一份拷贝，这份拷贝包含了几个重要的信息

1. 页表根地址
2. 在建立页表时申请的物理页帧
3. 建立映射的虚拟地址

我们会根据第三个信息，将页表中所有包含写标志位的映射的`D`位置置为0，这样当父进程或者子进程进行写时就会触发异常，对这个异常，父子进程都会取消掉这段映射，并申请页面来重新映射这段虚拟地址，拷贝数据，设置相应的标志位。

由于父子进程同时拥有上面提到的第二个信息，而当进程退出时，页表会向内核回收这些申请的物理页帧，如果父进程提前退出，但是子进程仍然需要这些物理页，就会造成子进程在拷贝数据时出错，因为被回收的页面可能被清零或者被其它模块申请。

**物理页帧管理机构**的作用就是在物理页进行分配或者回收时记录物理页的持有情况：

1. 当物理页首次被分配时，其持有计数为1
2. 在需要共享物理页的位置，使用者需要手动添加其持有计数
3. 当物理页被回收时，管理机构首先递减持有计数，并在计数为0 时归还到伙伴系统中

WARN：这需要使用者小心物理页的共享情况

这个管理机构如何更高效管理这些信息呢？因为有时候其他模块会申请连续的多个页面，并在存在共享时递增这一个区间的持有计数。即我们需要记录单个物理页或者连续物理页的持有计数，为了简化，这里我们禁止出现将连续物理页拆分的情况，即不允许单独对连续区间中的子区间或者单个页面增加计数，毕竟既然作为一个整体被分配出去，就应该作为一个整体进行回收。

**物理页帧管理机构**的数据结构定义如下:

```rust
pub struct FrameRefManager {
    record: HashMap<usize, usize>,
}
```

其主要的成员函数有两个:

```rust
pub fn add_ref(&mut self, id: usize) -> usize {
        if let Some(count) = self.record.get_mut(&id) {
            *count += 1;
            *count
        } else {
            self.record.insert(id, 1);
            1
        }
    }
pub fn dec_ref(&mut self, id: usize) -> Option<usize> {
    if let Some(count) = self.record.get_mut(&id) {
        *count -= 1;
        if *count == 0 {
            self.record.remove(&id);
            let start_addr = id << FRAME_BITS;
            unsafe {
                core::ptr::write_bytes(start_addr as *mut u8, 0, FRAME_SIZE);
            }
            FRAME_ALLOCATOR.lock().free(id, 0).unwrap();
            return Some(id);
        }
    } else {
        panic!("dec {} ref error", id);
    }
    None
}
```

其职责就是为需要共享的物理页帧增加或减少引用计数，并在计数为0时回收到伙伴系统。

在执行fork时需要处理的一个细节是对于`trap_context`的处理，这被单独映射成了一页，并且里面存储了一个子进程独有信息，因此在进行COW时，这一页不能共享。

由于引入了物理页帧的引用计数，因此需要页表模块与内核部分一同处理页面的分配情况，这部分要小心处理，不然容易发生多释放的错误。



## 2023.6.15

1. 为内核添加`lazy page allocation` 功能

在进程进行`mmap`或者 `sbrk`操作时，由于应用程序不知道需要多大的空间，因此其可能会请求一个很大的内存区间，如果内核直接满足程序的要求，就会分配大量的内存，但是应用程序可能并不会使用所有分配的区域，因此一个方法就是延迟分配，内核在页表中建立一个无效的映射，当程序真正进行访问时，内核再进行实际的内存分配并建立有效映射。



## 2023.6.20

1. 修改`page-table`的实现，以更优雅的方式记录地址映射情况，减少手工管理物理页帧的麻烦
2. 添加`brk`和 `mmap` 的`lazy page allocation`功能

在处理`COW`时，需要考虑页表项无效的情况，这时候不需要共享页面，也不需要将写标志去除，只需要按照原样映射即可。



## 2023.6.21/6.24

1. 添加gui的支持，第一个测试程序`guitest`来自`rcore` ，主要使用的是**embedded-graphics** 库
2. 添加`slint` 框架的测试，显示一个简单的图形界面

<img src="assert/image-20230624171412459.png" alt="image-20230624171412459" style="zoom:50%;" />

由于包含图形界面的程序需要的栈空间较大，因此需要调高应用程序的栈大小。



## 2023.6.34

1. 添加内核同步原语`Mutex`， 来自https://gitee.com/chyyuu/kernel-sync?_from=gitee_search

此仓库包含了`spin_mutex`和`ticket_mutex`，但其限制了cpu数量为4,我们将定义cpu数量的代码在`build.rs`中重写。与多核启动的方式类似。

2. 修改内核使用的锁，替换成新的实现。只替换了部分。
3. 规范串口驱动的实现，思考如何将带等待队列的串口驱动独立出去。

由于串口内部使用了互斥锁，而这个锁一般被实现在内核中，这种外部模块依赖内核功能的情况是经常发生的，这里暂时想到的一个方法是看能不能使用接口来屏蔽掉这种依赖。


