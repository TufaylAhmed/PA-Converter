drop table cloud_default_apps;
create table cloud_default_apps AS
select * 
from default_applications 
where (container in (
"2ch",
"51.com",
"adobe-connect",
"adobe-connectnow",
"adobe-creative-cloud",
"aim",
"aim-express",
"ali-wangwang",
"amazon-cloud-drive",
"ameba-now",
"autodesk360",
"avaya-webalive",
"baidu-hi",
"bebo",
"boxnet",
"buddybuddy",
"chinaren",
"cisco-spark",
"cloudapp",
"concur",
"convo",
"daum",
"dcinside",
"dochub",
"docstoc",
"dropbox",
"egnyte",
"evernote",
"facebook",
"fetion",
"filestack",
"flickr",
"flixwagon",
"fuze-meeting",
"gatherplace",
"genesys",
"github",
"globalmeet",
"gmail",
"google-calendar",
"google-cloud-storage",
"google-docs",
"google-hangouts",
"google-plus",
"google-spaces",
"google-talk",
"google-translate",
"google-video",
"gotomypc",
"gotowebinar",
"hightail",
"huddle",
"hulu",
"hyves",
"icloud",
"imeet",
"imgur",
"instagram",
"issuu",
"join-me",
"jumpshare",
"kaixin",
"kaixin001",
"kakaotalk",
"linkedin",
"live-mesh",
"lotuslive",
"lucidpress",
"mail.ru",
"mail.ru-agent",
"noteworthy",
"maytech",
"meetup",
"mega",
"mendeley",
"mixi",
"ms-lync",
"ms-office365",
"ms-onedrive",
"msn",
"myspace",
"netease-webdisk",
"netflix",
"ning",
"odnoklassniki",
"onehub",
"pastebin",
"pinterest",
"pivotaltracker",
"powow",
"prezi",
"proofhub",
"qik",
"qq",
"readytalk",
"reddit",
"renren",
"salesforce",
"sap-jam",
"screencast",
"scribd",
"second-life",
"secure-data-space",
"sendthisfile",
"sharefile",
"sharevault",
"signiant",
"sina-uc",
"sina-weibo",
"skydrive",
"slack",
"slideshare",
"smartsheet",
"soundcloud",
"sourceforge",
"stocktwits",
"storify",
"teamup-calendar",
"teamviewer",
"thwapr",
"torch-browser",
"trello",
"tumblr",
"twitter",
"uc-yun",
"viber",
"vimeo",
"vine",
"virustotal",
"vkontakte",
"webex",
"wechat",
"weiyun",
"whatsapp",
"windows-azure",
"yahoo-im",
"youku",
"yousendit",
"youtube",
"yunpan360",
"yy-voice",
"zalo",
"zettahost") or 
      name like "google%" or
	  name like "hotmail%" or
	  name like "amazon%" OR
	  name like "apple-%" OR
name like 'adobe-update' OR
name like "lastpass" OR
	  name like "windows-push%" OR
name like "ms-product-activation" OR
name like "ms-update" OR
	  name like "bing-maps" OR
	  name like "itunes-%" OR
      name like "avast-av-update%" OR
      name like "avg-update%" OR
      name like "mcafee-update%" OR
name like "teamviewer-%" OR
name like "tinder%" OR
name like "xing" OR
name like "telegram%" OR
name like "snapchat%" OR
name like "spotify%" OR
name like "xbox-live%" OR
name like "tableau-public" OR
name like 'weather-desktop' OR
name like "steam%" OR
name like "samsung-update%" OR
name like "panda-update%" OR
name like "eset-update%" OR
name like "firefox-update%" OR
	  name like "360-safeguard-update" or
 	  name like "bet365" or
 	  name like "bitdefender" or
 	  name like "adobe-flash-socketpolicy-server" or
 	  name like "cnn-video" or
 	  name like "dailymotion" or
 	  name like "yahoo-web-analytics" or
 	  name like "java-update" or
 	  name like "ooyala" or
 	  name like "quora" or
 	  name like "stumbleupon" or
 	  name like "sway" or
 	  name like "watch-abc" or
 	  name like "photobucket" or
 	  name like 'boldchat-logmein' or
 	  name like 'foursquare' or
  	  name like 'dnscrypt' or
	  issaas = "yes"  
	  ) and technology != "peer-to-peer"