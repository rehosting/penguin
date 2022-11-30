import scrapy
from scrapy.http import Request
from scrapy.linkextractors import LinkExtractor

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys

REQUEST_FINGERPRINTER_IMPLEMENTATION = '2.6'

class FwSpider(scrapy.Spider):
    name = 'fw_spider'
    allowed_domains = ['localhost']
    #start_urls = [ 'http://panda.re']

    def __init__(self, start_url):
        options = Options()
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--headless')
        self.driver = webdriver.Chrome('/igloo/chromedriver', chrome_options=options)
        self.start_urls = [start_url]
        print("\n\nSTARTURLS:", self.start_urls)

        self.link_extractor = LinkExtractor()

    def parse(self, response):
        self.driver.get(response.url)
        for link in self.link_extractor.extract_links(response):
            print("LINK:", link.url)
            yield Request(link.url, callback=self.parse)

if __name__ == '__main__':
    from scrapy.crawler import CrawlerProcess
    process = CrawlerProcess({})
    process.crawl(FwSpider, start_urls=['http://panda.re'])
    process.start() # the script will block here until the crawling is finished
