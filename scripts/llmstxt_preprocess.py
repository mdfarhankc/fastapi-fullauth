"""mkdocs-llmstxt preprocess hook.

Content tabs (pymdownx.tabbed) render their titles in a separate label row,
which the plugin's autoclean removes. Without them llms-full.txt shows several
unlabeled code blocks (SQLAlchemy, SQLModel, Tortoise, Beanie) with nothing to
tell them apart. So mkdocs.yml disables autoclean, and this hook writes each
label above its tab's content before running the plugin's autoclean itself.
"""

from bs4 import BeautifulSoup
from mkdocs_llmstxt import autoclean


def preprocess(soup: BeautifulSoup, output: str) -> None:
    for tabbed_set in soup.select("div.tabbed-set"):
        labels_row = tabbed_set.select_one("div.tabbed-labels")
        if labels_row is None:
            continue
        labels = [label.get_text(strip=True) for label in labels_row.find_all("label")]
        blocks = tabbed_set.select("div.tabbed-content > div.tabbed-block")
        for label, block in zip(labels, blocks, strict=True):
            heading = soup.new_tag("p")
            strong = soup.new_tag("strong")
            strong.string = label
            heading.append(strong)
            block.insert(0, heading)
    autoclean(soup)
