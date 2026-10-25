"""Seed text for the DNS name model: common English words and well-known service names.

Small on purpose (the model only has to tell "pronounceable" from "random"); it is data, not code.
"""

WORDS = """
about above account active address admin after again agent alert allow almost alpha always amazon
analytics android answer apple apps archive area article assets audio auth autumn avatar azure
back backup banking base basic beach beta better billing black blog blue board book boot bootstrap
box brand bridge broadcast browser build business button cache calendar camera campus card care
cart catalog center chat check chrome city class clean clear click client clock cloud cloudflare
code coffee college color comcast common community company connect console contact content control
cookie core corporate counter course create credit cross custom daily dashboard data database
default delivery design desktop details device digital direct discord display doc docs domain
download drive dropbox early east edge education email employee engine enterprise events example
exchange express facebook family fast feature feed field file finance firewall first flash flight
float flow focus folder food forum free friend front game garden gateway general github global
gmail good google gradient graph green group guide hardware health help hello history home host
hotel house hub icon image index info inside install internet invoice jobs journal keyboard
kitchen lab language laptop launch learn legal library light line link linux live local login logs
lunch mail main manage maps market master media meet member memory menu message metrics micro
mobile model monitor morning movie music name native network news next night node north note notes
office online open orange order outlook package page paper partner password pay people phone photo
pixel planet play plugin policy portal post power press price print private product profile
project public queue quick radio ready record region release remote report research reset resource
result review river room router safe sales school science screen search secure security server
service settings share shop sign simple site small smart social software solution sound source
south space speed sport spring square staging start static station status store stream student
studio summer support surface sync system table team tech telegram test theme thread ticket time
token tools town track trade travel trust update upload user video view village virtual wallet
water weather web week welcome west wifi window winter wireless work world write yahoo yellow
youtube zone akamai amazonaws apple icloud microsoft office365 windowsupdate gstatic googleapis
doubleclick googleusercontent cloudfront fastly netflix spotify twitter linkedin instagram
whatsapp snapchat tiktok reddit wikipedia mozilla firefox ubuntu debian fedora python nodejs
docker kubernetes slack zoom skype teams dropbox box paypal stripe shopify wordpress medium github
gitlab bitbucket digitalocean heroku vercel netlify cloudflare ntp time pool mdns
local lan
""".split()  # noqa: SIM905 - a wrapped text block reads better than a list
