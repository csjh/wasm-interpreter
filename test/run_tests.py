import os

IGNORE_LIST = [
    # takes a very long time to run
    "skip-stack-guard-page",
    # also takes a very long time to run
    "memory_grow"
]

test_dir = os.path.dirname(os.path.realpath(__file__))

passed = 0
failed = 0

for file in os.listdir("core"):
    if file.endswith(".wast"):
        without_wast = file[: -len(".wast")]
        if without_wast in IGNORE_LIST:
            continue

        input_path = os.path.join(test_dir, "core", file)
        output_path = os.path.join(
            test_dir, "core/wast-json", f"{without_wast}-wast.json"
        )
        if os.system(f"wast2json {input_path} -o {output_path}") != 0:
            print(f"Failed to convert {input_path} to wast-json")
            continue

        print(f"Testing {file}")
        if os.system(f"./executor {output_path}") != 0:
            print(f"Failed: {file}\n")
            failed += 1
        else:
            print(f"Passed: {file}\n")
            passed += 1

print(f"Passed: {passed}, Failed: {failed}")
