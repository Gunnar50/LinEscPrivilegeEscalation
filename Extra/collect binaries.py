
from bs4 import BeautifulSoup
import requests

url = "http://gtfobins.github.io/"
result = requests.get(url).text
doc = BeautifulSoup(result, "html.parser")

dictionaries_list = []
for function in ["SUDO", "SUID"]:
    dictionaries_list.append({})  # append empty dictionary to the list
    tr_tag = doc.tbody.find_all("tr")  # find all <tr> tags
    for _a in tr_tag:
        a_tag = _a.find_all("a")  # find all <a> tags (links)
        bin_name = a_tag[0].text  # binary name

        bin_url = f"{url}gtfobins/{bin_name}/"
        bin_page = BeautifulSoup(requests.get(bin_url).text, "html.parser")  # access the respective binary page

        h2 = bin_page.find(id=function.lower())  # find tag with id same as the function
        if h2 is not None:
            ul = h2.find_next_sibling("ul")  # find the next <ul> sibling containing the <pre> tag
            pre_tag = ul.find("pre")  # find the <pre> tag inside the <ul>
            code_tag = pre_tag.find("code").text  # find the <code> tag and extract the text

            command_list = code_tag.strip().split("\n")

            # add the bin name and command to the dictionary in the format of key: value
            dictionaries_list[-1][bin_name] = command_list

sudo_binaries_dict = dictionaries_list[0]
suid_binaries_dict = dictionaries_list[1]

final_dict = {}
# merge the two dictionaries into one dictionary for simplicity
# the format of the final dict is key: value, where key is the binaries and value is a list containing two lists,
# the first list is for the SUDO commands and the second is for SUID commands.
for key in sorted(set(sudo_binaries_dict.keys()) | set(suid_binaries_dict.keys())):
    final_dict[key] = [sudo_binaries_dict.get(key, []), suid_binaries_dict.get(key, [])]

print(final_dict)



