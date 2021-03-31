import argparse
from tg import MinimalApplicationConfigurator
from wsgiref.simple_server import make_server

from miner.miner import RootController

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='AriCoin command line interface')

    parser.add_argument("--load-blockchain", action="store", type=str,
                        default=None,
                        help="input file for stored blockchain state")
    parser.add_argument("--miner-id", action="store", type=str,
                        default=None,
                        help="miner identity file (private id)")
    parser.add_argument("--port", action="store", type=int,
                        default=8080,
                        help="server port")

    args = parser.parse_args()

    # Configure a new minimal application with our root controller.
    config = MinimalApplicationConfigurator()
    config.update_blueprint({
        'root_controller': RootController(args.load_blockchain, args.miner_id)
    })

    # Serve the newly configured web application.
    print(f"Serving on port {args.port} ...")
    httpd = make_server('', args.port, config.make_wsgi_app())
    httpd.serve_forever()
