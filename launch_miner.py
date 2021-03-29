import argparse
from tg import MinimalApplicationConfigurator
from wsgiref.simple_server import make_server

from miner.miner import RootController

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='AriCoin command line interface')

    parser.add_argument("--load-blockchain", action="store", type=str,
                        default=None,
                        help="input file for stored blockchain state")

    args = parser.parse_args()

    # Configure a new minimal application with our root controller.
    config = MinimalApplicationConfigurator()
    config.update_blueprint({
        'root_controller': RootController(args.load_blockchain)
    })

    # Serve the newly configured web application.
    print("Serving on port 8080...")
    httpd = make_server('', 8080, config.make_wsgi_app())
    httpd.serve_forever()
