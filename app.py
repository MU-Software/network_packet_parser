import flask
import flask_restful
import packet_parser

app = flask.Flask(__name__, static_url_path='')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
api = flask_restful.Api(app)


class PacketParse(flask_restful.Resource):
    def post(self):
        try:
            packet_data = flask.request.form['packet_data'].strip()
            include_data = flask.request.form.get('include_data', '') == 'on'
            if not packet_data:
                return {
                    'success': False,
                    'status': 400,
                    'message': 'Got no input data',
                    'data': ''
                }, 400

            return {
                'success': True,
                'data': packet_parser.frame_str(
                            packet_parser.Ethernet(
                                flask.request.form['packet_data']).to_dict(include_frame_data=include_data)),
                'status': 200,
                'message': '',
            }, 200
        except:
            return {
                'success': False,
                'data': '',
                'status': 500,
                'message': 'Error occured while parsing packet.',
            }, 500

api.add_resource(PacketParse, '/packet')

@app.route('/')
def index_route():
    return flask.send_from_directory('templates', 'index.html')

@app.route('/static/<path:path>')
def static_route(path):
    return flask.send_from_directory('templates', path)

if __name__ == '__main__':
    app.run(port=8101, debug=False)