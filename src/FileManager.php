<?php

namespace Joblix\Common;

use Aws\S3\S3Client;
use League\Flysystem\Filesystem;
use League\Flysystem\Adapter\Local;
use League\Flysystem\AwsS3v3\AwsS3Adapter;

class FileManager
{
    /**
     * @var Filesystem $filesystem
     */
    private $filesystem;

    /**
     * @var string $url_prefix
     */
    private $url_prefix;

    /**
     * @param string $local_public_dir
     */
    public function __construct(string $local_public_dir)
    {
        if (getenv('S3_BUCKET')) {
            $this->filesystem = new Filesystem(new AwsS3Adapter(
                new S3Client([
                    'region' => getenv('S3_BUCKET_REGION'),
                    'version' => '2006-03-01'
                ]),
                getenv('S3_BUCKET'),
                'assets'
            ));
            $this->url_prefix = getenv('S3_BUCKET_URL' . '/assets/');
        } else {
            $this->filesystem = new Filesystem(new Local($local_public_dir . '/assets/'));
            $this->url_prefix = getenv('BASE_URL' . '/assets/');
        }
    }

    public function getFilesystem()
    {
        return $this->filesystem;
    }

    public function getUrlPrefix()
    {
        return $this->url_prefix;
    }

    public function url(string $path)
    {
        return $this->url_prefix . $path;
    }
}
