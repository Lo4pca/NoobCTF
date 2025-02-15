#谢谢你，chatgpt
import re
import json
from pathlib import Path
class BookmarkProcessor:
    def __init__(self, exclude_urls, bookmark_template):
        self.exclude_urls = exclude_urls
        self.bookmark_template = bookmark_template
        self.urls = set()
        self.bookmarks = ""
    def filter_url(self, content):
        #https://gist.github.com/gruber/8891611
        url_regex = re.compile(
            r"(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))"
        )
        matches = url_regex.findall(content)
        filtered_urls = {
            match for match in matches if not any(exclude in match for exclude in self.exclude_urls)
        }
        return list(filtered_urls)
    def process_json(self, path):
        with open(path, "r", encoding="utf-8") as f:
            content = json.load(f)
        for entry in content:
            urls = self.filter_url(entry.get("content", ""))
            self._add_bookmarks(urls)
    def process_csv(self, path):
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        for line in lines:
            urls = self.filter_url(line)
            self._add_bookmarks(urls)
    def _add_bookmarks(self, urls):
        for url in urls:
            if url not in self.urls:
                self.bookmarks += f'<DT><A HREF="{url}">{url}</A>\n'
                self.urls.add(url)
    def write_bookmarks(self, output_path):
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.bookmark_template.format(self.bookmarks.strip()))
def main():
    exclude_urls = [
        "www.w3.org/2000/svg", "forms.gle", "www.twitch.tv", "cdn.discordapp.com/emojis",
        "cdn.discordapp.com/avatars", "images-ext-1.discordapp.net/external", "lh3.googleusercontent.com",
        "cdn.discordapp.com/icons", "register", "lh4.googleusercontent.com", "discord.gg",
        "lh6.googleusercontent.com", ".png", ".jpg", "login", "amazonaws.com", "tenor.com", "wigle.net",
        "dcode.fr", "nmap.org", "gmail.com", ".py", "shellcraft.amd64.linux.sh", ".gov", "picoctf.net",
        "picoctf.org", "gchq.github.io/CyberChef", "imgur.com", "encrypted-tbn0.gstatic.com",
        "pbs.twimg.com", "github.com/bata24/gef", "pwnable.kr", "pwnable.tw", "letmegooglethat.com",
        "ibb.co", ".tar.gz", "webhook.site", ".gif"
    ]
    bookmark_template = """<DT><H3>Writeups</H3>
{}"""
    processor = BookmarkProcessor(exclude_urls, bookmark_template)
    mode = input("请输入文件格式(json/csv): ").strip().lower()
    if mode not in ("json", "csv"):
        print("此格式暂不支持")
        return
    path_prompt = f"请输入存储所有{mode}文件的文件夹的路径: "
    glob_pattern = f"**/*.{mode}"
    process_func = processor.process_json if mode == "json" else processor.process_csv
    input_path = Path(input(path_prompt).strip())
    if not input_path.exists():
        print("路径无效，请检查输入路径")
        return
    output_path = Path(input("请输入结果文件的路径: ").strip())
    for file in input_path.glob(glob_pattern):
        process_func(file)
    processor.write_bookmarks(f"{output_path}")
    print(f"书签已保存至: {output_path}")
if __name__ == "__main__":
    main()