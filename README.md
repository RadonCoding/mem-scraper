![](https://user-images.githubusercontent.com/86915746/217642381-40d52ae2-e706-46d0-ae8b-1f6de966ccd2.gif)

Usage:
```
Usage: mem-scraper.exe [option(s)]
Options:
-H --help Shows the usage of arguments
-P --pid The target process identifier
-N --name The target process name
-F --filter The regex strings have to match (default = none)
-T --target The place to search strings from (1 = heap, 2 = stack, default = both)
-D --delay Delay between scans in milliseconds (default = 1000)
```

### Prerequisites
1. Install [Visual Studio](https://visualstudio.microsoft.com/downloads) and enable **Desktop Development with C++**

### Compilation
This project uses ANSI strings and C++ 20. Make sure to also link ntdll.lib.

### Credits
This project is inspired by https://www.x86matthew.com/view_post?id=stack_scraper.

### Info
It works by reading the process memory of an external process and tries to find strings on the heap and the stack.

### Contributing
1. Fork it
2. Create your branch (`git checkout -b my-change`)
3. Commit your changes (`git commit -m "changed something"`)
4. Push to the branch (`git push origin my-change`)
5. Create new pull request
